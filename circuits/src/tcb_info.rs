struct TCBInfo {
    pceid: String,
    fmspc: String,
    tcb_levels: Vec<TCBLevelObj>,
}

struct TCBLevelObj {
    pcesvn: u64,
    sgx_tcb_comp_svn_arr: Vec<u64>,
    status: TCBStatus,
}

enum TCBStatus {
    OK,
    TcbSwHardeningNeeded,
    TcbConfigurationAndSwHardeningNeeded,
    TcbConfigurationNeeded,
    TcbOutOfDate,
    TcbOutOfDateConfigurationNeeded,
    TcbRevoked,
    TcbUnrecognized,
}
