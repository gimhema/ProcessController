use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead},
    path::Path,
    process::{Command, Child, Stdio},
    thread,
    time::Duration,
};
use sysinfo::{Pid, ProcessStatus, System};
use std::os::windows::process::CommandExt;

// 경로에서 실행 파일 이름을 추출하는 함수
fn extract_executable_name(path: &str) -> Option<String> {
    Path::new(path).file_name()?.to_str().map(|s| s.to_string())
}

// ExeList.txt 파일을 읽어 실행 파일 경로를 벡터로 반환하는 함수
fn read_exe_list(file_path: &str) -> io::Result<Vec<String>> {
    let file = File::open(file_path)?;
    let reader = io::BufReader::new(file);
    let mut paths = Vec::new();
    for line in reader.lines() {
        if let Ok(path) = line {
            paths.push(path);
        }
    }
    Ok(paths)
}

// 프로세스가 응답 없음 상태인지 확인하는 함수
fn is_process_not_responding(pid: Pid, system: &System) -> bool {
    if let Some(process) = system.process(pid) {
        matches!(process.status(), ProcessStatus::Dead | ProcessStatus::Unknown(_))
    } else {
        false
    }
}


// 주기적으로 프로세스를 체크하고 관리하는 함수
fn monitor_processes(process_map: &mut HashMap<String, Child>, exe_list: &[String]) {
    let mut system = System::new_all();
    system.refresh_all(); // 모든 프로세스 정보를 갱신

    for path in exe_list {
        if let Some(exec_name) = extract_executable_name(path) {
            // 이미 실행 중인지 확인
            let process_exists = system.processes().values().any(|p| {
                p.name().eq_ignore_ascii_case(&exec_name)
            });

            // 프로세스가 실행 중이 아닌 경우 새로 실행
            if !process_exists && !process_map.contains_key(&exec_name) {
                println!("Starting process: {}", exec_name);

                // Command 객체 생성 및 새 창에서 실행
                let mut cmd = Command::new(path);
                cmd.creation_flags(0x00000010); // CREATE_NEW_CONSOLE 플래그

                match cmd.spawn() {
                    Ok(child) => {
                        process_map.insert(exec_name.clone(), child);
                    }
                    Err(e) => {
                        println!("Failed to start {}: {}", exec_name, e);
                    }
                }
            }
        }
    }

    // 실행 중인 프로세스를 검사하여 응답 없음 상태인 경우 종료
    let mut terminated_processes = Vec::new();
    for (exec_name, child) in process_map.iter_mut() {
        let pid = Pid::from_u32(child.id()); // `u32`를 `Pid`로 변환
        if is_process_not_responding(pid, &system) {
            println!("Process {} is not responding. Terminating...", exec_name);
            if let Err(e) = child.kill() {
                println!("Failed to kill {}: {}", exec_name, e);
            } else {
                terminated_processes.push(exec_name.clone());
            }
        } else if let Ok(Some(status)) = child.try_wait() {
            // 프로세스가 정상적으로 종료된 경우
            println!("Process {} has exited with status: {:?}", exec_name, status);
            terminated_processes.push(exec_name.clone());
        }
    }

    // 강제 종료된 또는 정상 종료된 프로세스를 해시맵에서 제거
    for exec_name in terminated_processes {
        process_map.remove(&exec_name);
    }
}



fn main() -> io::Result<()> {
    let exe_list_path = "ExeList.txt"; // ExeList.txt 파일의 경로 설정
    let check_interval = Duration::from_secs(10); // 주기적으로 검사할 시간 간격 설정

    // ExeList.txt 파일을 읽어 실행 파일 경로들을 가져옴
    let exe_list = read_exe_list(exe_list_path)?;
    let mut process_map: HashMap<String, Child> = HashMap::new(); // (Pid, Child)에서 Child로 수정

    // 주기적으로 프로세스를 확인하고 관리하는 루프
    loop {
        monitor_processes(&mut process_map, &exe_list);
        thread::sleep(check_interval);
    }
}
