import angr
import time
import signal
from dataclasses import dataclass
from typing import Optional

@dataclass  
class AngrResult:
    timed_out:      bool
    error:          Optional[str]
    wall_time_s:    float
    states_explored: int
    crashed_states:  int

import multiprocessing

def _run_angr_worker(binary_path: str, result_dict: dict):
    try:
        import angr
        proj = angr.Project(binary_path, auto_load_libs=False, load_options={"except_missing_libs": True})
        state = proj.factory.entry_state(add_options={angr.options.LAZY_SOLVES})
        simgr = proj.factory.simulation_manager(state)
        simgr.run()
        
        states_explored = len(simgr.deadended) + len(simgr.active)
        crashed = len(simgr.unsat) + len(getattr(simgr, 'crashed', []))
        
        result_dict['states_explored'] = states_explored
        result_dict['crashed'] = crashed
        result_dict['error'] = None
    except Exception as e:
        result_dict['error'] = str(e)[:100]

def angr_triage(binary_path: str, timeout_s: int = 60) -> AngrResult:
    """
    Run angr with a realistic timeout.
    Uses multiprocessing to prevent angr C-extension crashes from killing the pipeline.
    """
    start = time.time()
    
    manager = multiprocessing.Manager()
    result_dict = manager.dict()
    result_dict['states_explored'] = 0
    result_dict['crashed'] = 0
    result_dict['error'] = "Unknown error"

    p = multiprocessing.Process(target=_run_angr_worker, args=(binary_path, result_dict))
    p.start()
    p.join(timeout_s)

    if p.is_alive():
        p.terminate()
        p.join()
        return AngrResult(
            timed_out=True,
            error="60s timeout",
            wall_time_s=round(time.time() - start, 2),
            states_explored=result_dict.get('states_explored', 0),
            crashed_states=result_dict.get('crashed', 0),
        )
    
    error = result_dict.get('error')
    return AngrResult(
        timed_out=False,
        error=error if error else None,
        wall_time_s=round(time.time() - start, 2),
        states_explored=result_dict.get('states_explored', 0),
        crashed_states=result_dict.get('crashed', 0),
    )
