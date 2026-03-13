# 해당 스크립트는 한 서비스에 서브 서비스별(WEB/WAS or AP 등)VM에 대한 서버 스펙 및 서버 대수 변경을 무중단으로 할 수 있음
# 타겟그룹의 경우 이름에 서비스와 서브 서비스명이 같이 들어있어야 함 ex) nolticket의 API서비스 TG : nolticket-lb-api-tg, nolticket의 관리자서비스 TG : nolticket-adm-tg
# 서버 생성시 서버명에 붙는 숫자가 제일 큰것을 기준으로 그다음 숫자로 서버명이 적용됨
# 해당 스크립트 기준은 서버이므로 이와 관련된 정보(서버 이미지, VPC, Subnet, NAS 번호)는 미리 json파일에 명시해야 함
# Subnet은 이중화 구성을 위해 2개여야 함
# 해당 내용은 2tier구조로 작성됨(WEB=LB, WAS=VM, DB=CDB)
# 해당 서비스의 모든 VM은 같은 NAS를 사용함
# 해당 스크립트는 NCP KR Region에서 동작함

import json
import subprocess
import re
import time
import logging
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
# [2] NCP 인프라 통신 모듈
# ---------------------------------------------------------

class NcloudManager:
    @staticmethod
    def call_api(cmd_list: List[str]) -> Optional[Dict[str, Any]]:
        try:
            cmd = [str(arg) for arg in cmd_list]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if result.returncode != 0:
                logging.error(f"❌ API 실패: {result.stderr or result.stdout}")
                return None
            return json.loads(result.stdout)
        except Exception as e:
            logging.error(f"❌ 시스템 에러: {str(e)}")
            return None

    def get_server_spec_code(self, cpu: int, mem: int, cpu_type: str, hypervisor: str) -> str:
        ratio = mem / cpu
        cat = "MICRO" if ratio == 1.0 else "HICPU" if ratio == 2.0 else "STAND" if ratio == 4.0 else "HIMEM"
        prefix = f"AMD.{cat}" if cpu_type.lower() == "amd" else cat
        pattern = rf".*\.VSVR\.{prefix}\.C{cpu:03}\.M{mem:03}\.G003$"
        res = self.call_api(["ncloud", "vserver", "getServerSpecList", "--regionCode", "KR", "--hypervisorTypeCodeList", hypervisor])
        if res:
            for item in res.get('getServerSpecListResponse', {}).get('serverSpecList', []):
                if re.match(pattern, item['serverProductCode']): return item['serverSpecCode']
        return "UNKNOWN_SPEC"

    def get_target_groups(self, server_type: str, service: str, vpc_id: str) -> List[dict]:
        res = self.call_api(["ncloud", "vloadbalancer", "getTargetGroupList", "--regionCode", "KR", "--vpcNo", vpc_id])
        tgs = []
        if res:
            for item in res.get('getTargetGroupListResponse', {}).get('targetGroupList', []):
                name = item['targetGroupName']
                if server_type.lower() in name.lower() and service.lower() in name.lower():
                    tgs.append({"name": name, "id": item['targetGroupNo']})
        return tgs

    def wait_for_status(self, server_ids: List[str], target_status: str, timeout: int = 900) -> bool:
        if not server_ids: return True
        start = time.time()
        while time.time() - start < timeout:
            res = self.call_api(["ncloud", "vserver", "getServerInstanceList", "--serverInstanceNoList"] + server_ids)
            if res:
                instances = res['getServerInstanceListResponse']['serverInstanceList']
                success_ones = [i for i in instances if i['serverInstanceStatus']['code'] == target_status]
                logging.info(f"⏳ 상태 대기 [{target_status}]: {len(success_ones)}/{len(server_ids)} 완료")
                if len(success_ones) == len(server_ids): return True
            time.sleep(15)
        return False

# ---------------------------------------------------------
# [3] 단계별 일괄 실행 엔진
# ---------------------------------------------------------

def execute_tasks(ctx: InfraContext, tasks: List[Task], mgr: NcloudManager, curr_map: Dict):
    create_tasks = [t for t in tasks if t.action == "CREATE_SERVER"]
    change_tasks = [t for t in tasks if t.action == "CHANGE_SPEC"]
    terminate_tasks = [t for t in tasks if t.action == "TERMINATE_SERVER"]

    # --- PHASE 1: 모든 서버 증설 ---
    if create_tasks:
        logging.info("🚀 [PHASE 1] 모든 서비스 증설 시작")
        all_new_ids = []
        task_new_ids = {}

        for task in create_tasks:
            current_ids = []
            for i in range(task.count):
                idx = task.start_index + i
                name = ctx.naming_format.format(service=ctx.service_name, type=task.server_type, index=idx)
                subnet = ctx.subnets[idx % len(ctx.subnets)]
                acg_str = ",".join(task.acg_list) if task.acg_list else "'324479','324408'"
                
                res = mgr.call_api([
                    "ncloud", "vserver", "createServerInstances", "--vpcNo", ctx.vpc_id, "--subnetNo", subnet,
                    "--serverName", name, "--serverImageNo", ctx.image_no, "--serverSpecCode", task.new_spec,
                    "--networkInterfaceList", f"networkInterfaceOrder=0, accessControlGroupNoList=[{acg_str}]",
                    "--loginKeyName", ctx.login_key
                ])
                if res:
                    sid = res['createServerInstancesResponse']['serverInstanceList'][0]['serverInstanceNo']
                    current_ids.append(sid); all_new_ids.append(sid)
            task_new_ids[id(task)] = current_ids

        if all_new_ids and mgr.wait_for_status(all_new_ids, "RUN"):
            for task in create_tasks:
                ids = task_new_ids[id(task)]
                nas_rules = [f"serverInstanceNo={sid},writeAccess=true" for sid in ids]
                mgr.call_api(["ncloud", "vnas", "addNasVolumeAccessControl", "--regionCode", "KR", "--nasVolumeInstanceNo", ctx.nas_no, "--accessControlRuleList"] + nas_rules)
                for tg in task.tg_list:
                    mgr.call_api(["ncloud", "vloadbalancer", "addTarget", "--targetGroupNo", tg['id'], "--targetNoList"] + ids)
        logging.info("✅ 증설 단계 완료")

    # --- PHASE 2: 스펙 변경 (가용성 기반 지능형 로직) ---
    if change_tasks:
        logging.info("🚀 [PHASE 2] 스펙 변경 시작 (가용성 기반 지능형 로직)")
        change_info = {} 
        all_batch_ids = []
        all_safe_ids = []

        for task in change_tasks:
            targets = task.target_ids
            total_insts = curr_map.get(task.server_type, [])
            total_count = len(total_insts)
            remained_count = total_count - len(targets)

            # 가용성 체크 및 그룹 분리
            if remained_count == 0:
                if total_count == 1:
                    logging.warning(f"⚠️ {task.server_type}는 서버가 1대뿐입니다. 작업 시 서비스 단절이 발생합니다.")
                    if input(f"   >> {task.server_type} 진행할까요? (y/n): ").lower() != 'y':
                        change_info[id(task)] = {'batch': [], 'safe': []}
                        continue
                    batch, safe = targets, []
                else:
                    logging.info(f"ℹ️ {task.server_type}는 가용 서버가 부족하여 1대를 보존분으로 분리합니다.")
                    batch, safe = targets[1:], [targets[0]]
            else:
                logging.info(f"ℹ️ {task.server_type}는 가용 서버({remained_count}대)가 존재하여 전량 일괄 처리합니다.")
                batch, safe = targets, []

            all_batch_ids.extend(batch)
            all_safe_ids.extend(safe)
            change_info[id(task)] = {'batch': batch, 'safe': safe}

        def process_batch_group(target_ids, label):
            if not target_ids: return
            logging.info(f"⏳ {label.upper()} 그룹 일괄 스펙 변경 시작 ({len(target_ids)}대)")
            
            # 1. TG 제거
            for task in change_tasks:
                ids = [sid for sid in change_info[id(task)][label] if sid in target_ids]
                if ids:
                    for tg in task.tg_list:
                        mgr.call_api(["ncloud", "vloadbalancer", "removeTarget", "--targetGroupNo", tg['id'], "--targetNoList"] + ids)

            # 2. 중지 -> 변경 -> 기동
            mgr.call_api(["ncloud", "vserver", "stopServerInstances", "--serverInstanceNoList"] + target_ids)
            if mgr.wait_for_status(target_ids, "NSTOP"):
                for task in change_tasks:
                    ids = [sid for sid in change_info[id(task)][label] if sid in target_ids]
                    for sid in ids:
                        mgr.call_api(["ncloud", "vserver", "changeServerInstanceSpec", "--serverInstanceNo", sid, "--serverSpecCode", task.new_spec])
                
                mgr.call_api(["ncloud", "vserver", "startServerInstances", "--serverInstanceNoList"] + target_ids)
                if mgr.wait_for_status(target_ids, "RUN"):
                    # 3. NAS ACL 및 TG 복구
                    nas_rules = [f"serverInstanceNo={sid},writeAccess=true" for sid in target_ids]
                    mgr.call_api(["ncloud", "vnas", "addNasVolumeAccessControl", "--regionCode", "KR", "--nasVolumeInstanceNo", ctx.nas_no, "--accessControlRuleList"] + nas_rules)
                    for task in change_tasks:
                        ids = [sid for sid in change_info[id(task)][label] if sid in target_ids]
                        if ids:
                            for tg in task.tg_list:
                                mgr.call_api(["ncloud", "vloadbalancer", "addTarget", "--targetGroupNo", tg['id'], "--targetNoList"] + ids)
                                print(tg['name'])
                                time.sleep(20) # TG 설정 변경 쿨타임(그동안 해당 TG이 적용되어 있는 LB내 다른 TG은 건들 수 없음)

        process_batch_group(all_batch_ids, 'batch')
        process_batch_group(all_safe_ids, 'safe')
        logging.info("✅ 스펙 변경 단계 완료")

    # --- PHASE 3: 모든 서버 삭제 ---
    if terminate_tasks:
        logging.info("🚀 [PHASE 3] 모든 서버 반납 시작")
        all_del_ids = []
        for task in terminate_tasks:
            all_del_ids.extend(task.target_ids)
            for tg in task.tg_list:
                mgr.call_api(["ncloud", "vloadbalancer", "removeTarget", "--targetGroupNo", tg['id'], "--targetNoList"] + task.target_ids)
        
        logging.info("⏳ 트래픽 드레인 대기 (20s)")
        time.sleep(20)
        
        mgr.call_api(["ncloud", "vserver", "stopServerInstances", "--serverInstanceNoList"] + all_del_ids)
        if mgr.wait_for_status(all_del_ids, "NSTOP"):
            mgr.call_api(["ncloud", "vserver", "terminateServerInstances", "--serverInstanceNoList"] + all_del_ids)
        logging.info("✅ 반납 단계 완료")

# ---------------------------------------------------------
# [4] 분석 로직
# ---------------------------------------------------------

def analyze_infrastructure(filename: str) -> Tuple[Optional[InfraContext], List[Task], Dict]:
    try:
        with open(filename, "r") as f: data = json.load(f)
        ctx = InfraContext(
            service_name=data['service'], vpc_id=data['network']['vpc'], subnets=data['network']['subnet'],
            image_no=data['image'], nas_no=data['nas'], naming_format=data['server_name_cfg']['format'],
            naming_pattern=data['server_name_cfg']['pattern']
        )
    except Exception as e:
        logging.error(f"파일 로드 실패: {e}"); return None, [], {}

    mgr = NcloudManager()
    res = mgr.call_api(["ncloud", "vserver", "getServerInstanceList", "--vpcNo", ctx.vpc_id])
    curr_map = defaultdict(list)
    if res:
        for inst in res.get('getServerInstanceListResponse', {}).get('serverInstanceList', []):
            if ctx.service_name not in inst['serverName']: continue
            if match := re.match(ctx.naming_pattern, inst['serverName']):
                _, s_type, s_idx = match.groups()
                curr_map[s_type].append({"id": inst['serverInstanceNo'], "index": int(s_idx), "spec": inst['serverSpecCode'],
                                         "acg": [str(a['accessControlGroupNo']) for a in inst.get('accessControlGroupList', [])]})

    tasks = []
    for s_type, s_cfg in data['server_list'].items():
        spec = mgr.get_server_spec_code(s_cfg['cpu'], s_cfg['memory'], s_cfg['cpu_type'], s_cfg['hypervisor'])
        currs = curr_map[s_type]
        tgs = mgr.get_target_groups(s_type, ctx.service_name, ctx.vpc_id)

        wrong_ids = [i['id'] for i in currs if i['spec'] != spec]
        if wrong_ids: tasks.append(Task("CHANGE_SPEC", s_type, target_ids=wrong_ids, new_spec=spec, tg_list=tgs))

        diff = s_cfg['count'] - len(currs)
        if diff > 0:
            last = max([i['index'] for i in currs]) if currs else 0
            tasks.append(Task("CREATE_SERVER", s_type, count=diff, start_index=last+1, new_spec=spec, tg_list=tgs, 
                              acg_list=currs[0]['acg'] if currs else []))
        elif diff < 0:
            sorted_currs = sorted(currs, key=lambda x: x['index'], reverse=True)
            tasks.append(Task("TERMINATE_SERVER", s_type, target_ids=[i['id'] for i in sorted_currs[:abs(diff)]], tg_list=tgs))
    
    return ctx, tasks, curr_map

if __name__ == "__main__":
    mgr = NcloudManager()
    infra_ctx, task_list, current_inventory = analyze_infrastructure("test.json")
    if task_list:
        logging.info(f"📢 분석 완료: {len(task_list)}개의 작업 항목 감지")

        print("="*50 + "\n")
        for t in task_list:
            logging.info(f"📋 [계획] {t.server_type}: {t.action} ({len(t.target_ids) or t.count}대)")
            print("="*50 + "\n")

        if input("\n🔔 작업을 시작할까요? (y/n): ").lower() == 'y':
            execute_tasks(infra_ctx, task_list, mgr, current_inventory)