import json
import re
import time
import logging
import hmac
import hashlib
import base64
import requests
import os
import sys
from dataclasses import dataclass, field
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s][%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# ---------------------------------------------------------
# [1] 데이터 구조 정의
# ---------------------------------------------------------

@dataclass
class InfraContext:
    service_name: str
    vpc_id: str
    subnets: List[str]
    image_no: str
    nas_no: str
    naming_format: str
    naming_pattern: str
    access_key: str
    secret_key: str
    login_key: str = "jwkim-cloit"

@dataclass
class Task:
    action: str
    server_type: str
    target_ids: List[str] = field(default_factory=list)
    count: int = 0
    new_spec: str = ""
    tg_list: List[dict] = field(default_factory=list)
    start_index: int = 0
    acg_list: List[str] = field(default_factory=list)

# ---------------------------------------------------------
# [2] NCP REST API 매니저 (멱등성 및 실시간 갱신 로직)
# ---------------------------------------------------------

class NcloudApiManager:
    def __init__(self, ctx: InfraContext):
        self.ctx = ctx
        self.base_url = "https://ncloud.apigw.ntruss.com"

    def _make_signature(self, method: str, uri: str, timestamp: str) -> str:
        secret_key = bytes(self.ctx.secret_key, 'UTF-8')
        message = f"{method} {uri}\n{timestamp}\n{self.ctx.access_key}"
        signing_key = hmac.new(secret_key, bytes(message, 'UTF-8'), digestmod=hashlib.sha256).digest()
        return base64.b64encode(signing_key).decode('UTF-8')

    def flatten_params(self, params: Dict, prefix: str = "") -> Dict:
        flat = {}
        for k, v in params.items():
            key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, list):
                for i, item in enumerate(v, 1):
                    if isinstance(item, dict):
                        flat.update(self.flatten_params(item, prefix=f"{key}.{i}"))
                    else:
                        flat[f"{key}.{i}"] = item
            elif isinstance(v, dict):
                flat.update(self.flatten_params(v, prefix=key))
            else:
                flat[key] = v
        return flat

    def call_api(self, method: str, service_uri: str, action: str, params: Dict = None) -> Optional[Dict]:
        path = f"{service_uri}/{action}"
        processed_params = {'responseFormatType': 'json'}
        if params:
            processed_params.update(self.flatten_params(params))

        req = requests.models.PreparedRequest()
        req.prepare_url(f"{self.base_url}{path}", processed_params)
        full_uri_for_sig = req.url.replace(self.base_url, "")

        timestamp = str(int(time.time() * 1000))
        headers = {
            'x-ncp-apigw-timestamp': timestamp,
            'x-ncp-iam-access-key': self.ctx.access_key,
            'x-ncp-apigw-signature-v2': self._make_signature(method, full_uri_for_sig, timestamp)
        }

        try:
            resp = requests.request(method, f"{self.base_url}{path}", headers=headers, params=processed_params, timeout=30)
            if resp.status_code not in [200, 201]:
                logging.error(f"❌ API 실패: {action} ({resp.status_code}) - {resp.text}")
                return None
            return resp.json()
        except Exception as e:
            logging.error(f"❌ API 통신 에러: {str(e)}")
            return None

    def get_current_inventory(self) -> Dict:
        """ 현재 실행 시점의 서버 맵을 실시간으로 가져옴 """
        res = self.call_api("GET", "/vserver/v2", "getServerInstanceList", {"vpcNo": self.ctx.vpc_id})
        curr_map = defaultdict(list)
        if res:
            for inst in res.get('getServerInstanceListResponse', {}).get('serverInstanceList', []):
                name = inst['serverName']
                if self.ctx.service_name not in name: continue
                if match := re.match(self.ctx.naming_pattern, name):
                    _, s_type, s_idx = match.groups()
                    curr_map[s_type].append({"id": inst['serverInstanceNo'], "spec": inst['serverSpecCode']})
        return curr_map

    def wait_for_lb_used(self, tg_no: str, timeout: int = 600):
        res_tg = self.call_api("GET", "/vloadbalancer/v2", "getTargetGroupList", {"targetGroupNoList": [tg_no]})
        if not res_tg: return
        tg_list = res_tg.get('getTargetGroupListResponse', {}).get('targetGroupList', [])
        if not tg_list: return
        lb_no = tg_list[0].get('loadBalancerInstanceNo')
        if not lb_no: return

        logging.info(f"⏳ 로드밸런서 설정 적용 대기 (LB: {lb_no})...")
        start = time.time()
        while time.time() - start < timeout:
            res_lb = self.call_api("GET", "/vloadbalancer/v2", "getLoadBalancerInstanceDetail", {"loadBalancerInstanceNo": lb_no})
            if res_lb:
                lb_detail = res_lb.get('getLoadBalancerInstanceDetailResponse', {}).get('loadBalancerInstanceList', [{}])[0]
                if lb_detail.get('loadBalancerInstanceStatusName', {}) == "Running":
                    return True
            time.sleep(15)
        return False

    def wait_for_status(self, server_ids: List[str], target_status: str, timeout: int = 900) -> bool:
        if not server_ids: return True
        start = time.time()
        while time.time() - start < timeout:
            res = self.call_api("GET", "/vserver/v2", "getServerInstanceList", {"serverInstanceNoList": server_ids})
            if res:
                instances = res.get('getServerInstanceListResponse', {}).get('serverInstanceList', [])
                success_ones = [i for i in instances if i['serverInstanceStatus']['code'] == target_status]
                if len(success_ones) == len(server_ids): return True
            time.sleep(15)
        return False

# ---------------------------------------------------------
# [3] 단계별 일괄 실행 엔진
# ---------------------------------------------------------

def execute_tasks(ctx: InfraContext, tasks: List[Task], api: NcloudApiManager):
    create_tasks = [t for t in tasks if t.action == "CREATE_SERVER"]
    change_tasks = [t for t in tasks if t.action == "CHANGE_SPEC"]
    terminate_tasks = [t for t in tasks if t.action == "TERMINATE_SERVER"]

    # PHASE 1: 일괄 증설
    if create_tasks:
        logging.info("🚀 [PHASE 1] 모든 서비스 증설 시작")
        all_new_ids, task_new_ids = [], {}
        for task in create_tasks:
            current_ids = []
            for i in range(task.count):
                idx = task.start_index + i
                name = ctx.naming_format.format(service=ctx.service_name, type=task.server_type, index=idx)
                params = {
                    "vpcNo": ctx.vpc_id, "subnetNo": ctx.subnets[idx % len(ctx.subnets)],
                    "serverName": name, "serverImageNo": ctx.image_no, "serverSpecCode": task.new_spec,
                    "loginKeyName": ctx.login_key,
                    "networkInterfaceList": [{"networkInterfaceOrder": 0, "accessControlGroupNoList": task.acg_list if task.acg_list else ["324479", "324408"]}]
                }
                res = api.call_api("POST", "/vserver/v2", "createServerInstances", params)
                if res:
                    sid = res['createServerInstancesResponse']['serverInstanceList'][0]['serverInstanceNo']
                    current_ids.append(sid); all_new_ids.append(sid)
            task_new_ids[id(task)] = current_ids

        if all_new_ids and api.wait_for_status(all_new_ids, "RUN"):
            for task in create_tasks:
                ids = task_new_ids[id(task)]
                nas_params = {"nasVolumeInstanceNo": ctx.nas_no, "accessControlRuleList": [{"serverInstanceNo": sid, "writeAccess": "true"} for sid in ids]}
                api.call_api("POST", "/vnas/v2", "addNasVolumeAccessControl", nas_params)
                for tg in task.tg_list:
                    api.call_api("POST", "/vloadbalancer/v2", "addTarget", {"targetGroupNo": tg['id'], "targetNoList": ids})
                    api.wait_for_lb_used(tg['id'])
        logging.info("✅ 증설 단계 완료")

    # PHASE 2: 지능형 스펙 변경 (실시간 인벤토리 반영 버전)
    if change_tasks:
        logging.info("🚀 [PHASE 2] 스펙 변경 시작 (실시간 가용성 체크)")
        # !!! 중요: PHASE 1에서 생성된 서버들을 가용 대수에 포함시키기 위해 인벤토리 재조회 !!!
        live_inventory = api.get_current_inventory()
        
        change_info = {}
        all_batch_ids, all_safe_ids = [], []

        for task in change_tasks:
            targets = task.target_ids
            # live_inventory를 사용하여 현재 정확한 서버 대수 파악
            total_insts = live_inventory.get(task.server_type, [])
            total_count = len(total_insts)
            remained_count = total_count - len(targets)

            logging.info(f"📊 {task.server_type} 분석: 전체 {total_count}대 / 변경대상 {len(targets)}대 / 유지 {remained_count}대")

            if remained_count == 0:
                if total_count == 1:
                    logging.warning(f"⚠️ {task.server_type}는 서버가 1대뿐입니다. 순단 발생!")
                    if input(f"   >> 진행하시겠습니까? (y/n): ").lower() != 'y':
                        change_info[id(task)] = {'batch': [], 'safe': []}; continue
                    batch, safe = targets, []
                else:
                    batch, safe = targets[1:], [targets[0]]
            else:
                batch, safe = targets, []

            all_batch_ids.extend(batch); all_safe_ids.extend(safe)
            change_info[id(task)] = {'batch': batch, 'safe': safe}

        def process_group(target_ids, label):
            if not target_ids: return
            logging.info(f"⏳ {label.upper()} 그룹 스펙 변경 시작 ({len(target_ids)}대)")
            
            # 멱등성: 현재 스펙을 확인하여 이미 변경된 서버는 제외하고 작업 리스트 생성 가능 (생략)
            for task in change_tasks:
                ids = [sid for sid in change_info[id(task)][label] if sid in target_ids]
                for tg in task.tg_list:
                    api.call_api("POST", "/vloadbalancer/v2", "removeTarget", {"targetGroupNo": tg['id'], "targetNoList": ids})
                    api.wait_for_lb_used(tg['id'])

            api.call_api("POST", "/vserver/v2", "stopServerInstances", {"serverInstanceNoList": target_ids})
            if api.wait_for_status(target_ids, "NSTOP"):
                for task in change_tasks:
                    ids = [sid for sid in change_info[id(task)][label] if sid in target_ids]
                    for sid in ids:
                        # 멱등성: 실제 스펙 변경이 필요한 경우만 호출하도록 개선 가능
                        api.call_api("POST", "/vserver/v2", "changeServerInstanceSpec", {"serverInstanceNo": sid, "serverSpecCode": task.new_spec})
                
                api.call_api("POST", "/vserver/v2", "startServerInstances", {"serverInstanceNoList": target_ids})
                if api.wait_for_status(target_ids, "RUN"):
                    nas_params = {"nasVolumeInstanceNo": ctx.nas_no, "accessControlRuleList": [{"serverInstanceNo": sid, "writeAccess": "true"} for sid in target_ids]}
                    api.call_api("POST", "/vnas/v2", "addNasVolumeAccessControl", nas_params)
                    for task in change_tasks:
                        ids = [sid for sid in change_info[id(task)][label] if sid in target_ids]
                        for tg in task.tg_list:
                            api.call_api("POST", "/vloadbalancer/v2", "addTarget", {"targetGroupNo": tg['id'], "targetNoList": ids})
                            api.wait_for_lb_used(tg['id'])

        process_group(all_batch_ids, 'batch')
        process_group(all_safe_ids, 'safe')
        logging.info("✅ 스펙 변경 단계 완료")

    # PHASE 3: 모든 서버 반납
    if terminate_tasks:
        logging.info("🚀 [PHASE 3] 모든 서버 반납 시작")
        all_del_ids = [sid for t in terminate_tasks for sid in t.target_ids]
        for task in terminate_tasks:
            for tg in task.tg_list:
                api.call_api("POST", "/vloadbalancer/v2", "removeTarget", {"targetGroupNo": tg['id'], "targetNoList": task.target_ids})
                api.wait_for_lb_used(tg['id'])
        
        time.sleep(20) # Drain 대기
        api.call_api("POST", "/vserver/v2", "stopServerInstances", {"serverInstanceNoList": all_del_ids})
        if api.wait_for_status(all_del_ids, "NSTOP"):
            api.call_api("POST", "/vserver/v2", "terminateServerInstances", {"serverInstanceNoList": all_del_ids})
        logging.info("✅ 반납 단계 완료")

# ---------------------------------------------------------
# [4] 분석 로직 (최초 실행 계획 수립)
# ---------------------------------------------------------

def analyze_infrastructure(filename: str, access_key: str, secret_key: str) -> Tuple[Optional[InfraContext], List[Task]]:
    try:
        with open(filename, "r") as f: data = json.load(f)
        ctx = InfraContext(
            service_name=data['service'], vpc_id=data['network']['vpc'], subnets=data['network']['subnet'],
            image_no=data['image'], nas_no=data['nas'], naming_format=data['server_name_cfg']['format'],
            naming_pattern=data['server_name_cfg']['pattern'], access_key=access_key, secret_key=secret_key
        )
    except Exception as e:
        logging.error(f"파일 로드 실패: {e}"); return None, []

    api = NcloudApiManager(ctx)
    res_inst = api.call_api("GET", "/vserver/v2", "getServerInstanceList", {"vpcNo": ctx.vpc_id})
    curr_map = defaultdict(list)
    if res_inst:
        for inst in res_inst.get('getServerInstanceListResponse', {}).get('serverInstanceList', []):
            name = inst['serverName']
            if ctx.service_name not in name: continue
            if match := re.match(ctx.naming_pattern, name):
                _, s_type, s_idx = match.groups()
                curr_map[s_type].append({"id": inst['serverInstanceNo'], "index": int(s_idx), "spec": inst['serverSpecCode'],
                                         "acg": [str(a['accessControlGroupNo']) for a in inst.get('accessControlGroupList', [])]})

    res_tg = api.call_api("GET", "/vloadbalancer/v2", "getTargetGroupList", {"vpcNo": ctx.vpc_id, "regionCode": "KR"})
    tg_all = res_tg.get('getTargetGroupListResponse', {}).get('targetGroupList', []) if res_tg else []

    tasks = []
    for s_type, s_cfg in data['server_list'].items():
        res_spec = api.call_api("GET", "/vserver/v2", "getServerSpecList", {"regionCode": "KR", "hypervisorTypeCodeList": [s_cfg.get('hypervisor', 'XEN')]})
        spec_code = "UNKNOWN"
        ratio = s_cfg['memory'] / s_cfg['cpu']
        pattern = rf".*\.VSVR\.{('AMD.' if s_cfg.get('cpu_type', '').lower() == 'amd' else '')}{('MICRO' if ratio == 1.0 else 'HICPU' if ratio == 2.0 else 'STAND' if ratio == 4.0 else 'HIMEM')}\.C{s_cfg['cpu']:03}\.M{s_cfg['memory']:03}\.G003$"
        if res_spec:
            for item in res_spec.get('getServerSpecListResponse', {}).get('serverSpecList', []):
                if re.match(pattern, item['serverProductCode']): spec_code = item['serverSpecCode']; break

        tgs = [{"name": t['targetGroupName'], "id": t['targetGroupNo']} for t in tg_all if s_type.lower() in t['targetGroupName'].lower() and ctx.service_name.lower() in t['targetGroupName'].lower()]
        currs = curr_map[s_type]
        wrong_ids = [i['id'] for i in currs if i['spec'] != spec_code]
        if wrong_ids: tasks.append(Task("CHANGE_SPEC", s_type, target_ids=wrong_ids, new_spec=spec_code, tg_list=tgs))
        diff = s_cfg['count'] - len(currs)
        if diff > 0:
            last = max([i['index'] for i in currs]) if currs else 0
            tasks.append(Task("CREATE_SERVER", s_type, count=diff, start_index=last+1, new_spec=spec_code, tg_list=tgs, acg_list=currs[0]['acg'] if currs else []))
        elif diff < 0:
            sorted_currs = sorted(currs, key=lambda x: x['index'], reverse=True)
            tasks.append(Task("TERMINATE_SERVER", s_type, target_ids=[i['id'] for i in sorted_currs[:abs(diff)]], tg_list=tgs))
    
    return ctx, tasks

if __name__ == "__main__":
    try:
        MY_ACCESS_KEY = os.environ['NCLOUD_ACCESS_KEY']
        MY_SECRET_KEY = os.environ['NCLOUD_SECRET_KEY']
    except KeyError:
        print("환경변수 설정을 확인 부탁드립니다.")
        sys.exit(1)

    
    infra_ctx, task_list = analyze_infrastructure("test.json", MY_ACCESS_KEY, MY_SECRET_KEY)
    if task_list:

        logging.info(f"📢 분석 완료: {len(task_list)}개의 작업 감지\n")

        print("="*50)
        for t in task_list:
            logging.info(f"📋 [계획] {t.server_type}: {t.action} ({len(t.target_ids) or t.count}대)")
            print("="*50)

        api_mgr = NcloudApiManager(infra_ctx)
        if input("\n🔔 작업을 시작할까요? (y/n): ").lower() == 'y':
            execute_tasks(infra_ctx, task_list, api_mgr)