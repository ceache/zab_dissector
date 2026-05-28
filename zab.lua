--------------------------------------------------------------------------------
-- zab.lua
--
-- Works as of Wireshark v4.6.2
-- This is a Lua dissector for ZAB 1.0 validation.
-- Only the messages exchanged between the client and the server are supported.
--
-- Notice:
-- The default port is set to 2181, but keep in mind that clients can connect to
-- the Zookeeper server using any port configured in the configuration file.
--
-- Setup
--   Windows:
--     1. Copy 'zab.lua' to somewhere in your wireshark directory. For example, C:\Program Files\Wireshark.
--     2. Open 'init.lua' in your wireshark root directory. Comment the line 'disable_lua = true' or change it to 'disable_lua = false'.
--   Linux/MacOS
--     1. Open/Create 'init.lua' in your Wireshark config directory, '~/.config/wireshark', with the line 'disable_lua = false'
--     2. Copy 'zab.lua' to your plugins directory '~/.config/wireshark/plugins' (you may have to create it)
--
--------------------------------------------------------------------------------

-- TODOs:
-- SASL packets
-- Logging config and functions, and replace all prints

local DEFAULT_ZAB_PORT = 2181
local MAX_REQUEST_SIZE = 100 * 1024 * 1024

local FOUR_LETTER_WORDS = {
    ["conf"] = true,
    ["cons"] = true,
    ["crst"] = true,
    ["dump"] = true,
    ["envi"] = true,
    ["ruok"] = true,
    ["srst"] = true,
    ["srvr"] = true,
    ["stat"] = true,
    ["wchs"] = true,
    ["wchc"] = true,
    ["wchp"] = true,
    ["mntr"] = true
}

local FIXED_XIDS = {
    [0] = "CONNECT_XID",
    [-1] = "WATCH_XID",
    [-2] = "PING_XID",
    [-4] = "AUTH_XID",
    [-8] = "SET_WATCHES_XID"
}

local opCodes = {
    -- [0] = "CONNECT",  unused?
    [1] = "CREATE",
    [2] = "DELETE",
    [3] = "EXISTS",
    [4] = "GETDATA",
    [5] = "SETDATA",
    [6] = "GETACL",
    [7] = "SETACL",
    [8] = "GETCHILDREN",
    [9] = "SYNC",
    [11] = "PING",
    [12] = "GETCHILDREN2",
    [13] = "CHECK",
    [14] = "MULTI",
    [15] = "CREATE2",
    [16] = "RECONFIG",
    [19] = "CREATE_CONTAINER",
    [21] = "CREATE_TTL",
    [-10] = "CREATESESSION",
    [-11] = "CLOSE",
    [100] = "SETAUTH",
    [101] = "SETWATCHES"
}

local watchEventTypes = {
    [-1] = "None",
    [1] = "NodeCreated",
    [2] = "NodeDeleted",
    [3] = "NodeDataChanged",
    [4] = "NodeChildrenChanged"
}

local errorCodes = {
    [0] = "Success",
    [-1] = "SystemZookeeperError",
    [-2] = "RuntimeInconsistencyError",
    [-3] = "DataInconsistencyError",
    [-4] = "ConnectionLossError",
    [-5] = "MarshallingError",
    [-6] = "UnimplementedError",
    [-7] = "OperationTimeoutError",
    [-8] = "BadArgumentsError",
    [-13] = "NewConfigNoQuorumError",
    [-14] = "ReconfigInProcessError",
    [-100] = "APIError",
    [-101] = "NoNodeError",
    [-102] = "NoAuthError",
    [-103] = "BadVersionError",
    [-108] = "NoChildrenForEphemeralsError",
    [-110] = "NodeExistsError",
    [-111] = "NotEmptyError",
    [-112] = "SessionExpiredError",
    [-113] = "InvalidCallbackError",
    [-114] = "InvalidACLError",
    [-115] = "AuthFailedError",
    [-118] = "NotReadOnlyCallError",
    [-119] = "ConnectionClosedError",
}

local f_pkt             = ProtoField.none("zab.pkt", "Packet")
local f_op              = ProtoField.none("zab.op", "Operation")

local f_4lw             = ProtoField.string("zab.4lw", "4LW message")
local f_protoversion    = ProtoField.uint64("zab.protocolversion", "Protocol Version")
local f_zxid            = ProtoField.uint64("zab.zxid", "ZxID", base.HEX)
local f_zxid_epoch      = ProtoField.uint32("zab.zxid.epoch", "Epoch")
local f_zxid_count      = ProtoField.uint32("zab.zxid.count", "Count")
local f_czxid           = ProtoField.uint64("zab.czxid", "Created ZxID", base.HEX)
local f_czxid_epoch     = ProtoField.uint32("zab.czxid.epoch", "Epoch")
local f_czxid_count     = ProtoField.uint32("zab.czxid.count", "Count")
local f_mzxid           = ProtoField.uint64("zab.mzxid", "Last Modified ZxID", base.HEX)
local f_mzxid_epoch     = ProtoField.uint32("zab.mzxid.epoch", "Epoch")
local f_mzxid_count     = ProtoField.uint32("zab.mzxid.count", "Count")
local f_pzxid           = ProtoField.uint64("zab.pzxid", "Last Modified Children ZxID", base.HEX)
local f_pzxid_epoch     = ProtoField.uint32("zab.pzxid.epoch", "Epoch")
local f_pzxid_count     = ProtoField.uint32("zab.pzxid.count", "Count")
local f_timeout         = ProtoField.uint32("zab.timeout", "Timeout")
local f_session         = ProtoField.uint64("zab.session", "Session ID", base.HEX)
local f_len             = ProtoField.uint32("zab.length", "Length", base.INT)
local f_passwd          = ProtoField.bytes("zab.passwd", "Password")
local f_xid             = ProtoField.int32("zab.xid", "Transaction ID", base.INT)
local f_opCode          = ProtoField.int32("zab.opcode", "OpCode", base.INT, opCodes)
local f_data            = ProtoField.bytes("zab.data", "Data")
local f_path            = ProtoField.string("zab.path", "Path")
local f_watch           = ProtoField.bool("zab.watch", "Watch")
local f_ctime           = ProtoField.uint64("zab.ctime", "Created", base.RELATIVE_TIME)
local f_mtime           = ProtoField.uint64("zab.mtime", "Last Modified", base.RELATIVE_TIME)
local f_ephemeralowner  = ProtoField.uint64("zab.ephemeralowner", "Ephemeral Owner", base.HEX)
local f_numchildren     = ProtoField.uint64("zab.numchildren", "Number of Children")
local f_datalength      = ProtoField.uint64("zab.datalength", "Data Length")
local f_done            = ProtoField.bool("zab.done", "Done")
local f_err             = ProtoField.int64("zab.err", "Error", base.INT, errorCodes)
local f_perms           = ProtoField.int64("zab.permissions", "Permissions")
local f_authtype        = ProtoField.int32("zab.authtype", "Authentication Type")
local f_scheme          = ProtoField.string("zab.scheme", "Scheme")
local f_credential      = ProtoField.string("zab.credential", "Credentials")
local f_flags           = ProtoField.uint32("zab.flags", "Flags", base.HEX)
local f_ephemeral       = ProtoField.bool("zab.ephemeral", "Ephemeral")
local f_sequence        = ProtoField.bool("zab.sequence", "Sequence")
local f_container       = ProtoField.bool("zab.container", "Container")
local f_ttl             = ProtoField.uint64("zab.ttl", "TTL")
local f_joining         = ProtoField.string("zab.joining", "Joining")
local f_leaving         = ProtoField.string("zab.leaving", "Leaving")
local f_newmembers      = ProtoField.string("zab.newmembers", "New Members")
local f_config_id       = ProtoField.uint64("zab.config_id", "Config ID", base.HEX)
local f_version         = ProtoField.uint64("zab.version", "Version")
local f_cversion        = ProtoField.uint64("zab.cversion", "Child Version")
local f_aversion        = ProtoField.uint64("zab.aversion", "ACL Version")
local f_readonly        = ProtoField.bool("zab.readonly", "Readonly")
local f_eventtype       = ProtoField.uint32("zab.eventtype", "Event Type", base.INT, watchEventTypes)
local f_count           = ProtoField.uint32("zab.count", "Count")
local f_state           = ProtoField.uint32("zab.state", "State")
local f_child           = ProtoField.string("zab.child", "Child")


local CLIENTS = {}

local Direction = {
    Client2Server = 1,
    Server2Client = 2,
}

local DissRes = {
    Error = false,
    Client = Direction.Client2Server,
    Server = Direction.Server2Client,
}


------------------------------------------------------------------------------
local function defaultDissect(buf, pkt, tree, _offset, _stat)
    tree:append_text(" [NO IMPL]")
    if buf:len() > 0 then
        tree:add(f_data, buf)
    end
    return true
end

local function dispatch(table, index)
    if table[index] == nil then
        return defaultDissect
    end

    return table[index]
end

------------------------------------------------------------------------------
local function parseStat(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 8 > remain then return -1, nil end
    local czxid = buf(offset, 8)
    offset = offset + 8
    if offset + 8 > remain then return -1, nil end
    local mzxid= buf(offset, 8)
    offset = offset + 8
    if offset + 16 > remain then return -1, nil end
    local ctime = buf(offset, 8)
    local mtime = buf(offset + 8, 8)
    offset = offset + 16
    if offset + 12 > remain then return -1, nil end
    local version = buf(offset, 4)
    local cversion = buf(offset + 4, 4)
    local aversion = buf(offset + 8, 4)
    offset = offset + 12
    if offset + 16 > remain then return -1, nil end
    local ephemeralowner = buf(offset, 8)
    local datalength = buf(offset + 8, 4)
    local numchildren = buf(offset + 12, 4)
    offset = offset + 16
    if offset + 8 > remain then return -1, nil end
    local pzxid = buf(offset, 8)
    offset = offset + 8

    return offset, {
        czxid=czxid,
        mzxid=mzxid,
        ctime=ctime,
        mtime=mtime,
        version=version,
        cversion=cversion,
        aversion=aversion,
        ephemeralowner=ephemeralowner,
        datalength=datalength,
        numchildren=numchildren,
        pzxid=pzxid
    }
end

local function reprStat(stat, tree)
    local t_zxid = tree:add(f_czxid, stat.czxid)
    t_zxid:add(f_czxid_epoch, stat.czxid(0, 4))
    t_zxid:add(f_czxid_count, stat.czxid(4, 4))
    local t_zxid = tree:add(f_mzxid, stat.mzxid)
    t_zxid:add(f_mzxid_epoch, stat.mzxid(0, 4))
    t_zxid:add(f_mzxid_count, stat.mzxid(4, 4))
    tree:add(f_ctime, stat.ctime)
    tree:add(f_mtime, stat.mtime)
    tree:add(f_version, stat.version)
    tree:add(f_cversion, stat.cversion)
    tree:add(f_aversion, stat.aversion)
    tree:add(f_ephemeralowner, stat.ephemeralowner)
    tree:add(f_datalength, stat.datalength)
    tree:add(f_numchildren, stat.numchildren)
    local t_zxid = tree:add(f_pzxid, stat.pzxid)
    t_zxid:add(f_pzxid_epoch, stat.pzxid(0, 4))
    t_zxid:add(f_pzxid_count, stat.pzxid(4, 4))
end

-- Reads a string, returns length,str or 0,nil
local function parseString(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 4 > remain then return -1, nil end
    local str_length = buf(offset, 4):int()
    offset = offset + 4
    if str_length == -1 then str_length = 0 end -- XXX: Is this correct??
    if offset + str_length > remain then return -1, nil end
    local str = buf(offset, str_length)
    offset = offset + str_length

    return offset, str
end

local function parseAcl(buf)
    -- 4 bytes perms, 4 bytes scheme length, scheme
    local offset = 0
    local remain = buf:len()
    if offset + 4 > remain then return -1, nil end
    local perms = buf(offset, 4)
    offset = offset + 4
    local scheme_offset, scheme = parseString(buf(offset))
    if scheme_offset == -1 then return -1, nil end
    offset = offset + scheme_offset
    local cred_offset, credential = parseString(buf(offset))
    if cred_offset == -1 then return -1, nil end
    offset = offset + cred_offset

    return offset, {
        perms=perms,
        scheme=scheme,
        credential=credential
    }
end

local function reprAcl(acl, tree)
    tree:add(f_perms, acl.perms)
    tree:add(f_scheme, acl.scheme)
    tree:add(f_credential, acl.credential)
end

local function parseAclsArray(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 4 > remain then return -1, nil end
    local acls_count = buf(offset, 4):int()
    offset = offset + 4
    local acls = {}
    for i = 0, acls_count - 1 do
        local acl_offset, acl = parseAcl(buf(offset))
        if acl_offset == -1 then return -1, nil end
        offset = offset + acl_offset
        table.insert(acls, acl)
    end

    return offset, acls
end

local function reprAclsArray(acls, tree)
    for i, acl in ipairs(acls) do
        reprAcl(acl, tree)
    end
end

------------------------------------------------------------------------------
local function parseResult(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 8 > remain then return -1, nil end
    local zxid = buf(offset, 8)
    offset = offset + 8
    if offset + 4 > remain then return -1, nil end
    local err = buf(offset, 4)
    offset = offset + 4

    return offset, {
        zxid=zxid,
        err=err
    }
end

local function reprResult(result, tree)
    local t_zxid = tree:add(f_zxid, result.zxid)
    t_zxid:add(f_zxid_epoch, result.zxid(0, 4))
    t_zxid:add(f_zxid_count, result.zxid(4, 4))
    tree:add(f_err, result.err)
end

------------------------------------------------------------------------------
-- CHECK packets

local function parseCheckRequest(buf)
    local offset = 0
    local remain = buf:len()

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    if offset + 4 > remain then return -1, nil end
    local version = buf(offset, 4)
    offset = offset + 4

    return offset, {
        path=path,
        version=version,
    }
end

local function reprCheckRequest(check_req, tree)
    tree:add(f_path, check_req.path)
    tree:add(f_version, check_req.version)
end

local function dissectCheckRequest(buf, pkt, tree, _state)
    local offset, check_req = parseCheckRequest(buf)
    if offset == -1 then return false end
    tree:append_text(" [CHECK]")
    reprCheckRequest(check_req, tree)
    return DissRes.Client
end

local function parseCheckReply(buf)
    -- Nothing to do
end

local function reprCheckReply(check_rep, tree)
    -- Nothing to do
end

local function dissectCheckReply(buf, pkt, tree, _state)
    -- Nothing to do
end

------------------------------------------------------------------------------
-- GETCHILDREN / GETCHILDREN2 packets

local function parseGetChildrenRequest(buf)
    local offset = 0
    local remain = buf:len()

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    if offset + 1 > remain then return -1, nil end
    local watch = buf(offset, 1)
    offset = offset + 1

    return offset, {
        path=path,
        watch=watch,
    }
end

local function dissectGetChildrenRequest(buf, pkt, tree, _state)
    local offset, getchildren_req = parseGetChildrenRequest(buf)
    if offset == -1 then return false end
    tree:add(f_path, getchildren_req.path)
    tree:add(f_watch, getchildren_req.watch)
    return DissRes.Client
end

local function dissectGetChildren2Request(buf, pkt, tree, _state)
    local offset, getchildren_req = parseGetChildrenRequest(buf)
    if offset == -1 then return false end
    tree:add(f_path, getchildren_req.path)
    tree:add(f_watch, getchildren_req.watch)
    return DissRes.Client
end

local function parseGetChildrenReply(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 4 > remain then return -1, nil end
    local count = buf(offset, 4)
    offset = offset + 4
    local children = {}
    for i = 0, count:int() - 1 do
        local child_offset, child = parseString(buf(offset))
        if child_offset == -1 then return -1, nil end
        offset = offset + child_offset
        table.insert(children, child)
    end

    return offset, {
        count=count,
        children=children,
    }
end

local function dissectGetChildrenReply(buf, pkt, tree, _state)
    local offset, getchildren_rep = parseGetChildrenReply(buf)
    if offset == -1 then return false end

    tree:add(f_count, getchildren_rep.count)
    for i, child in ipairs(getchildren_rep.children) do
        tree:add(f_child, child)
    end
    return DissRes.Server
end

local function parseGetChildren2Reply(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 4 > remain then return -1, nil end
    local count = buf(offset, 4)
    offset = offset + 4
    local children = {}
    for i = 0, count:uint() - 1 do
        local child_offset, child = parseString(buf(offset))
        if child_offset == -1 then return -1, nil end
        offset = offset + child_offset
        table.insert(children, child)
    end
    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        count=count,
        children=children,
        stat=stat
    }
end

local function dissectGetChildren2Reply(buf, pkt, tree, _state)
    local offset, getchildren2_rep = parseGetChildren2Reply(buf)
    if offset == -1 then return false end

    tree:add(f_count, getchildren2_rep.count)
    for i, child in ipairs(getchildren2_rep.children) do
        tree:add(f_child, child)
    end
    reprStat(getchildren2_rep.stat, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- SET ACLS packets

local function parseSetAclRequest(buf)
    local offset = 0
    local remain = buf:len()

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    local acls_offset, acls = parseAclsArray(buf(offset))
    if acls_offset == -1 then return -1, nil end
    offset = offset + acls_offset
    if offset + 4 > remain then return -1, nil end
    local version = buf(offset, 4)
    offset = offset + 4

    return offset, {
        path=path,
        acls=acls,
        version=version,
    }
end

local function dissectSetAclRequest(buf, pkt, tree, _state)
    local offset, setacl_req = parseSetAclRequest(buf)
    if offset == -1 then return false end
    tree:add(f_path, setacl_req.path)
    reprAclsArray(setacl_req.acls, tree)
    tree:add(f_version, setacl_req.version)
    return DissRes.Client
end

local function parseSetAclReply(buf)
    local offset = 0

    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        stat=stat
    }
end

local function dissectSetAclReply(buf, pkt, tree, _state)
    local offset, setacl_rep = parseSetAclReply(buf)
    if offset == -1 then return false end

    reprStat(setacl_rep.stat, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- GET ACLS packets

local function parseGetAclRequest(buf)
    local offset = 0

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset


    return offset, {
        path=path,
    }
end

local function dissectGetAclRequest(buf, pkt, tree, _state)
    local offset, getacl_req = parseGetAclRequest(buf)
    if offset == -1 then return false end
    tree:add(f_path, getacl_req.path)
    return DissRes.Client
end

local function parseGetAclReply(buf)
    local offset = 0

    local acls_offset, acls = parseAclsArray(buf(offset))
    if acls_offset == -1 then return -1, nil end
    offset = offset + acls_offset
    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        acls=acls,
        stat=stat,
    }
end

local function dissectGetAclReply(buf, pkt, tree, _state)
    local offset, getacl_rep = parseGetAclReply(buf)
    if offset == -1 then return false end
    reprAclsArray(getacl_rep.acls, tree)
    reprStat(getacl_rep.stat, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- SET DATA packets

local function parseSetDataRequest(buf)
    local offset = 0
    local remain = buf:len()

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    local data_offset, data = parseString(buf(offset))
    if data_offset == -1 then return -1, nil end
    offset = offset + data_offset
    if offset + 4 > remain then return -1, nil end
    local version = buf(offset, 4)
    offset = offset + 4

    return offset, {
        path=path,
        data=data,
        version=version,
    }
end

local function reprSetDataRequest(setdata_req, tree)
    tree:add(f_path, setdata_req.path)
    tree:add(f_data, setdata_req.data)
    tree:add(f_version, setdata_req.version)
end

local function dissectSetDataRequest(buf, pkt, tree, _state)
    local offset, setdata_req = parseSetDataRequest(buf)
    if offset == -1 then return false end
    reprSetDataRequest(setdata_req, tree)
    return DissRes.Client
end

local function parseSetDataReply(buf)
    local offset = 0

    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        stat=stat
    }
end

local reprSetDataReply = reprStat

local function dissectSetDataReply(buf, pkt, tree, _state)
    local offset, setdata_rep = parseSetDataReply(buf)
    if offset == -1 then return false end

    reprSetDataReply(setdata_rep.stat, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- GET DATA packets

local function parseGetDataRequest(buf)
    local offset = 0
    local remain = buf:len()
    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    if offset + 1 > remain then return -1, nil end
    local watch = buf(offset, 1)
    offset = offset + 1

    return offset, {
        path=path,
        watch=watch,
    }
end

local function dissectGetDataRequest(buf, pkt, tree, _state)
    local offset, getdata_req = parseGetDataRequest(buf)
    if offset == -1 then return false end
    tree:add(f_path, getdata_req.path)
    tree:add(f_watch, getdata_req.watch)
    return DissRes.Client
end

local function parseGetDataReply(buf)
    local offset = 0
    local data_offset, data = parseString(buf(offset))
    if data_offset == -1 then return -1, nil end
    offset = offset + data_offset
    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        data=data,
        stat=stat
    }
end

local function dissectGetDataReply(buf, pkt, tree, _state)
    local offset, getdata_rep = parseGetDataReply(buf)
    if offset == -1 then return false end
    tree:add(f_data, getdata_rep.data)
    reprStat(getdata_rep.stat, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- CLOSE packets

local function dissectCloseRequest(buf, pkt, tree, _state)
    return DissRes.Client
end

local function dissectCloseReply(buf, pkt, tree, state)
    -- FIXME: Do this here or in top level somehow?
    -- Clear all pending requests
    for i, xid in ipairs(state.xids) do
        state.xids[xid] = nil
    end
    return DissRes.Server
end

------------------------------------------------------------------------------
-- DELETE packets

local function parseDeleteRequest(buf)
    local offset = 0
    local remain = buf:len()

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    if offset + 4 > remain then return -1, nil end
    local version = buf(offset, 4)
    offset = offset + 4

    return offset, {
        path=path,
        version=version,
    }
end

local function reprDeleteRequest(delete_req, tree)
    tree:add(f_path, delete_req.path)
    tree:add(f_version, delete_req.version)
end

local function dissectDeleteRequest(buf, pkt, tree, _state)
    local offset, delete_req = parseDeleteRequest(buf)
    if offset == -1 then return false end
    reprDeleteRequest(delete_req, tree)
    return DissRes.Client
end

local function parseDeleteReply(buf)
    -- Nothing to parse
    return 0, {}
end

local function reprDeleteReply(delete_rep, tree)
    -- Nothing to repr
    return
end

local function dissectDeleteReply(buf, pkt, tree, _state)
    local offset, delete_rep = parseDeleteReply(buf)
    if offset == -1 then return false end
    return DissRes.Server
end

------------------------------------------------------------------------------
-- EXISTS packets

local function parseExistsRequest(buf)
    local offset = 0
    local remain = buf:len()
    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    if offset + 1 > remain then return -1, nil end
    local watch = buf(offset, 1)
    offset = offset + 1

    return offset, {
        path=path,
        watch=watch,
    }
end

local function dissectExistsRequest(buf, pkt, tree, _state)
    local offset, exists_req = parseExistsRequest(buf)
    if offset == -1 then return false end
    tree:add(f_path, exists_req.path)
    tree:add(f_watch, exists_req.watch)
    return DissRes.Client
end

local function parseExistsReply(buf)
    local offset = 0
    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        stat=stat,
    }
end

local function dissectExistsReply(buf, pkt, tree, _state)
    local offset, exists_rep = parseExistsReply(buf)
    if offset == -1 then return false end
    reprStat(exists_rep.stat, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- RECONFIG packets

local function parseReconfigRequest(buf)
    local offset = 0
    local remain = buf:len()

    local joining_offset, joining = parseString(buf(offset))
    if joining_offset == -1 then return -1, nil end
    offset = offset + joining_offset
    local leaving_offset, leaving = parseString(buf(offset))
    if leaving_offset == -1 then return -1, nil end
    offset = offset + leaving_offset
    local new_members_offset, new_members = parseString(buf(offset))
    if new_members_offset == -1 then return -1, nil end
    offset = offset + new_members_offset
    if offset + 8 > remain then return -1, nil end
    local config_id = buf(offset, 8)
    offset = offset + 8

    return offset, {
        joining=joining,
        leaving=leaving,
        new_members=new_members,
        config_id=config_id,
    }
end

local function reprReconfigRequest(reconfig_req, tree)
    tree:add(f_joining, reconfig_req.joining)
    tree:add(f_leaving, reconfig_req.leaving)
    tree:add(f_newmembers, reconfig_req.new_members)
    tree:add(f_config_id, reconfig_req.config_id)
end

local function dissectReconfigRequest(buf, pkt, tree, _state)
    local offset, reconfig_req = parseReconfigRequest(buf)
    if offset == -1 then return false end
    reprReconfigRequest(reconfig_req, tree)
    return DissRes.Client
end

local function parseReconfigReply(buf)
    local offset = 0
    local data_offset, data = parseString(buf(offset))
    if data_offset == -1 then return -1, nil end
    offset = offset + data_offset
    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        data=data,
        stat=stat,
    }
end

local function reprReconfigReply(reconfig_rep, tree)
    reprStat(reconfig_rep.stat, tree)
end

local function dissectReconfigReply(buf, pkt, tree, _state)
    local offset, reconfig_rep = parseReconfigReply(buf)
    if offset == -1 then return false end
    reprReconfigReply(reconfig_rep, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- SYNC packets

local function parseSyncRequest(buf)
    local offset = 0

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset

    return offset, {
        path=path
    }
end

local function reprSyncRequest(sync_req, tree)
    tree:add(f_path, sync_req.path)
end

local function dissectSyncRequest(buf, pkt, tree, _state)
    local offset, sync_req = parseSyncRequest(buf)
    if offset == -1 then return false end
    tree:append_text(" [SYNC]")
    reprSyncRequest(sync_req, tree)
    return DissRes.Client
end

local function parseSyncReply(buf)
    local offset = 0

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset

    return offset, {
        path=path
    }
end

local function reprSyncReply(sync_rep, tree)
    tree:add(f_path, sync_rep.path)
end

local function dissectSyncReply(buf, pkt, tree, _state)
    local offset, sync_rep = parseSyncReply(buf)
    if offset == -1 then return false end
    tree:append_text(" [SYNC REP]")
    reprSyncReply(sync_rep, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- CREATE // CREATE2 // CREATE_TTL // CREATE_CONTAINER packets

local function parseCreateRequest(buf)
    local offset = 0
    local remain = buf:len()
    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    local data_offset, data = parseString(buf(offset))
    if data_offset == -1 then return -1, nil end
    offset = offset + data_offset
    local acls_offset, acls = parseAclsArray(buf(offset))
    if acls_offset == -1 then return -1, nil end
    offset = offset + acls_offset
    if offset + 4 > remain then return -1, nil end
    local flags = buf(offset, 4)
    offset = offset + 4

    return offset, {
        path=path,
        data=data,
        acls=acls,
        flags=flags,
    }
end

local function reprCreateRequest(create_req, tree)
    tree:add(f_path, create_req.path)
    tree:add(f_data, create_req.data)
    reprAclsArray(create_req.acls, tree)
    local t_flags = tree:add(f_flags, create_req.flags)
    local ephemeral = (bit.band(create_req.flags:uint(), 0x1) == 1)
    local sequence = (bit.band(create_req.flags:uint(), 0x2) == 2)
    local container = (bit.band(create_req.flags:uint(), 0x4) == 4)
    t_flags:add(f_ephemeral, ephemeral)
    t_flags:add(f_sequence, sequence)
    t_flags:add(f_container, container)
end

local function dissectCreateRequest(buf, pkt, tree, _state)
    local offset, create_req = parseCreateRequest(buf)
    if offset == -1 then return false end
    reprCreateRequest(create_req, tree)
    return DissRes.Client
end

local function parseCreateReply(buf)
    local offset = 0
    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset

    return offset, {
        path=path
    }
end

local function reprCreateReply(create_rep, tree)
    tree:add(f_path, create_rep.path)
end

local function dissectCreateReply(buf, pkt, tree, _state)
    local offset, create_rep = parseCreateReply(buf)
    if offset == -1 then return false end
    reprCreateReply(create_rep, tree)
    return DissRes.Server
end


local parseCreate2Request = parseCreateRequest

local reprCreate2Request = reprCreateRequest

local function dissectCreate2Request(buf, pkt, tree, _state)
    local offset, create_req = parseCreate2Request(buf)
    if offset == -1 then return false end
    reprCreate2Request(create_req, tree)
    return DissRes.Client
end

local function parseCreate2Reply(buf)
    local offset = 0

    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset

    local stat_offset, stat = parseStat(buf(offset))
    if stat_offset == -1 then return -1, nil end
    offset = offset + stat_offset

    return offset, {
        path=path,
        stat=stat,
    }
end

local function reprCreate2Reply(create_rep, tree)
    tree:add(f_path, create_rep.path)
    reprStat(create_rep.stat, tree)
end

local function dissectCreate2Reply(buf, pkt, tree, _state)
    local offset, create_rep = parseCreate2Reply(buf)
    if offset == -1 then return false end
    reprCreate2Reply(create_rep, tree)
    return DissRes.Server
end


local parseCreateContainerRequest = parseCreateRequest

local reprCreateContainerRequest = reprCreateRequest

local function dissectCreateContainerRequest(buf, pkt, tree, _state)
    local offset, create_container_req = parseCreateContainerRequest(buf)
    if offset == -1 then return false end
    reprCreateContainerRequest(create_container_req, tree)
    return DissRes.Client
end

local parseCreateContainerReply = parseCreate2Reply

local reprCreateContainerReply = reprCreate2Reply

local function dissectCreateContainerReply(buf, pkt, tree, _state)
    local offset, create_container_rep = parseCreateContainerReply(buf)
    if offset == -1 then return false end
    reprCreateContainerReply(create_container_rep, tree)
    return DissRes.Server
end


local function parseCreateTTLRequest(buf)
    local offset = 0
    local remain = buf:len()
    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset
    local data_offset, data = parseString(buf(offset))
    if data_offset == -1 then return -1, nil end
    offset = offset + data_offset
    local acls_offset, acls = parseAclsArray(buf(offset))
    if acls_offset == -1 then return -1, nil end
    offset = offset + acls_offset
    if offset + 4 > remain then return -1, nil end
    local flags = buf(offset, 4)
    offset = offset + 4
    if offset + 8 > remain then return -1, nil end
    local ttl = buf(offset, 8)
    offset = offset + 8

    return offset, {
        path=path,
        data=data,
        acls=acls,
        flags=flags,
        ttl=ttl,
    }
end

local function reprCreateTTLRequest(create_ttl_req, tree)
    tree:add(f_path, create_ttl_req.path)
    tree:add(f_data, create_ttl_req.data)
    reprAclsArray(create_ttl_req.acls, tree)
    local t_flags = tree:add(f_flags, create_ttl_req.flags)
    local ephemeral = (bit.band(create_ttl_req.flags:uint(), 0x1) == 1)
    local sequence = (bit.band(create_ttl_req.flags:uint(), 0x2) == 2)
    local container = (bit.band(create_ttl_req.flags:uint(), 0x4) == 4)
    t_flags:add(f_ephemeral, ephemeral)
    t_flags:add(f_sequence, sequence)
    t_flags:add(f_container, container)
    tree:add(f_ttl, create_ttl_req.ttl)
end

local function dissectCreateTTLRequest(buf, pkt, tree, _state)
    local offset, create_ttl_req = parseCreateTTLRequest(buf)
    if offset == -1 then return false end
    reprCreateTTLRequest(create_ttl_req, tree)
    return DissRes.Client
end

local parseCreateTTLReply = parseCreate2Reply

local reprCreateTTLReply = reprCreate2Reply

local function dissectCreateTTLReply(buf, pkt, tree, _state)
    local offset, create_ttl_rep = parseCreateTTLReply(buf)
    if offset == -1 then return false end
    reprCreateTTLReply(create_ttl_rep, tree)
    return DissRes.Server
end


------------------------------------------------------------------------------
-- MULTI packets

local parseReqOpCode = {
    [1] = parseCreateRequest,
    [2] = parseDeleteRequest,
    [3] = parseExistsRequest,
    [4] = parseGetDataRequest,
    [5] = parseSetDataRequest,
    [6] = parseGetAclRequest,
    [7] = parseSetAclRequest,
    [8] = parseGetChildrenRequest,
    [9] = parseSyncRequest,
    [12] = parseGetChildrenRequest,
    [13] = parseCheckRequest,
    [15] = parseCreate2Request,
    [19] = parseCreateContainerRequest,
    [21] = parseCreateTTLRequest,
}

local parseRepOpCode = {
    [1] = parseCreateReply,
    [2] = parseDeleteReply,
    [3] = parseExistsReply,
    [4] = parseGetDataReply,
    [5] = parseSetDataReply,
    [6] = parseGetAclReply,
    [7] = parseSetAclReply,
    [8] = parseGetChildrenReply,
    [9] = parseSyncReply,
    [12] = parseGetChildren2Reply,
    [13] = parseCheckReply,
    [15] = parseCreate2Reply,
    [19] = parseCreateContainerReply,
    [21] = parseCreateTTLReply,
}

local reprReqOpCode = {
    [1] = reprCreateRequest,
    [2] = reprDeleteRequest,
    -- [3] = reprExistsRequest,
    -- [4] = reprGetDataRequest,
    [5] = reprSetDataRequest,
    -- [6] = reprGetAclRequest,
    -- [7] = reprSetAclRequest,
    -- [8] = reprGetChildrenRequest,
    [9] = reprSyncRequest,
    -- [12] = reprGetChildrenRequest,
    [13] = reprCheckRequest,
    [15] = reprCreate2Request,
    [19] = reprCreateContainerRequest,
    [21] = reprCreateTTLRequest,
}

local reprRepOpCode = {
    [1] = reprCreateReply,
    [2] = reprDeleteReply,
    -- [3] = reprExistsReply,
    -- [4] = reprGetDataReply,
    [5] = reprSetDataReply,
    -- [6] = reprGetAclReply,
    -- [7] = reprSetAclReply,
    -- [8] = reprGetChildrenReply,
    [9] = reprSyncReply,
    -- [12] = reprGetChildren2Reply,
    [13] = reprCheckReply,
    [15] = reprCreate2Reply,
    [19] = reprCreateContainerReply,
    [21] = reprCreateTTLReply,
}

local function parseMultiRequest(buf)
    local offset = 0
    local remain = buf:len()
    local ops = {}
    repeat
        local start_offset = offset
        if offset + 9 > remain then return -1, nil end
        local opcode = buf(offset, 4)
        local done = buf(offset + 4, 1)
        local err = buf(offset + 5, 4)
        -- print("XXX Multi opCode", offset, opcode, done, err)
        offset = offset + 9
        if done:int() == 1 then break end
        -- PARSE the opCode here
        local req_parse_fun = parseReqOpCode[opcode:int()]
        -- print("XXX Multi fun", req_parse_fun)
        if req_parse_fun == nil then return -1, nil end
        local req_offset, req_data = req_parse_fun(buf(offset))
        if req_offset == -1 then return -1, nil end
        local req_raw_data = buf(offset, req_offset)
        -- print("XXX Multi req_data", req_offset, req_data, req_raw_data)
        offset = offset + req_offset
        local op_data = buf(start_offset, 9 + req_offset)

        table.insert(ops, {
            opcode=opcode,
            done=done,
            err=err,
            req_data=req_data,
            req_raw_data=req_raw_data,
            op_data=op_data
        })
    until done == 1

    return offset, {
        ops=ops,
    }
end

local function dissectMultiRequest(buf, pkt, tree, _state)
    local offset, multi_req = parseMultiRequest(buf)
    if offset == -1 then return false end

    for i, op in ipairs(multi_req.ops) do
        local t_multi = tree:add(f_op)
        t_multi:add(f_opCode, op.opcode)
        t_multi:add(f_done, op.done)
        t_multi:add(f_err, op.err)
        local reprFun = reprReqOpCode[op.opcode:int()]
        if reprFun ~= nil then
            reprFun(op.req_data, t_multi)
        else
            t_multi:add(f_data, op.req_raw_data)
        end
    end

    return DissRes.Client
end

local function parseMultiReply(buf)
    local offset = 0
    local remain = buf:len()
    -- print("XXX Multi len", remain)

    local ops = {}
    repeat
        local start_offset = offset
        if offset + 9 > remain then return -1, nil end
        local opcode = buf(offset, 4)
        local done = buf(offset + 4, 1)
        local err = buf(offset + 5, 4)
        -- print("XXX MultiRep opCode", offset, opcode, done, err)
        offset = offset + 9
        if done:int() == 1 then break end
        -- PARSE the opCode here
        local rep_parse_fun = parseRepOpCode[opcode:int()]
        -- print("XXX Multi fun", rep_parse_fun)
        if rep_parse_fun == nil then return -1, nil end
        local rep_offset, rep_data = rep_parse_fun(buf(offset))
        if rep_offset == -1 then return -1, nil end
        local rep_raw_data = buf(offset, rep_offset)
        -- print("XXX Multi rep_data", rep_offset, rep_data, rep_raw_data)
        offset = offset + rep_offset
        -- print("XXX Multi op_data", start_offset, offset)
        local op_data = buf(start_offset, 9 + rep_offset)

        table.insert(ops, {
            opcode=opcode,
            done=done,
            err=err,
            rep_data=rep_data,
            rep_raw_data=rep_raw_data,
            op_data=op_data,
        })
    until done == 1

    return offset, {
        ops=ops,
    }
end

local function dissectMultiReply(buf, pkt, tree, _state)
    local offset, multi_rep = parseMultiReply(buf)
    if offset == -1 then return false end

    for i, op in ipairs(multi_rep.ops) do
        local t_multi = tree:add(f_op, op.op_data)
        t_multi:add(f_opCode, op.opcode)
        t_multi:add(f_done, op.done)
        t_multi:add(f_err, op.err)
        local reprFun = reprRepOpCode[op.opcode:int()]
        if reprFun ~= nil then
            reprFun(op.rep_data, t_multi)
        else
            t_multi:add(f_data, op.rep_raw_data)
        end
    end

    return DissRes.Server
end

------------------------------------------------------------------------------
-- opCode dispatcher
local dissectReqOpCode = {
    [-11] = dissectCloseRequest,
    [1] = dissectCreateRequest,
    [2] = dissectDeleteRequest,
    [3] = dissectExistsRequest,
    [4] = dissectGetDataRequest,
    [5] = dissectSetDataRequest,
    [6] = dissectGetAclRequest,
    [7] = dissectSetAclRequest,
    [8] = dissectGetChildrenRequest,
    [9] = dissectSyncRequest,
    [12] = dissectGetChildren2Request,
    [13] = dissectCheckRequest,
    [14] = dissectMultiRequest,
    [15] = dissectCreate2Request,
    [16] = dissectReconfigRequest,
    [19] = dissectCreateContainerRequest,
    [21] = dissectCreateTTLRequest,
}

local dissectRepOpCode = {
    [-11] = dissectCloseReply,
    [1] = dissectCreateReply,
    -- [2] = dissectDeleteReply,
    [3] = dissectExistsReply,
    [4] = dissectGetDataReply,
    [5] = dissectSetDataReply,
    [6] = dissectGetAclReply,
    [7] = dissectSetAclReply,
    [8] = dissectGetChildrenReply,
    [9] = dissectSyncReply,
    [12] = dissectGetChildren2Reply,
    -- [13] = dissectCheckReply,
    [14] = dissectMultiReply,
    [15] = dissectCreate2Reply,
    [16] = dissectReconfigReply,
    [19] = dissectCreateContainerReply,
    [21] = dissectCreateTTLReply,
}

local function dispatchOpCodeDissector(buf, pkt, tree, state, opCode)
    -- Dissect a request/reply based on opCode (with a default fallback)
    if state.dir == Direction.Client2Server then
        return dispatch(dissectReqOpCode, opCode)(buf, pkt, tree, state)
    elseif state.dir == Direction.Server2Client then
        return dispatch(dissectRepOpCode, opCode)(buf, pkt, tree, state)
    elseif state.dir == nil then
        -- Try to parse as client packet then as server packet
        local res = dispatch(dissectReqOpCode, opCode)(buf, pkt, tree, state)
        if res == false then
            res = dispatch(dissectRepOpCode, opCode)(buf, pkt, tree, state)
        end
        return res
    end
end

------------------------------------------------------------------------------
-- 4LW

local function dissect4lw(buf, pkt, tree)
    local fourlw = buf(0, 4):string()
    local res = nil
    if FOUR_LETTER_WORDS[fourlw] ~= nil then
        pkt.cols.info:set(
            string.format("4LW %s request", fourlw)
        )
        res = Direction.Client2Server
    else
        pkt.cols.info:set("4LW reply")
        res = true -- Direction.Server2Client
    end
    tree:append_text(" [4LW]")
    tree:add(f_4lw, buf())
    return res
end

------------------------------------------------------------------------------
-- Watch Event

local function parseWatchEvent(buf)
    local offset = 0
    local remain = buf:len()
    -- Result fields
    local result_offset, result = parseResult(buf(offset))
    if result_offset == -1 then return -1, nil end
    offset = offset + result_offset
    if offset + 4 > remain then return -1, nil end
    local eventtype = buf(offset, 4)
    offset = offset + 4
    if offset + 4 > remain then return -1, nil end
    local state = buf(offset, 4)
    offset = offset + 4
    local path_offset, path = parseString(buf(offset))
    if path_offset == -1 then return -1, nil end
    offset = offset + path_offset

    return offset, {
        result=result,
        eventtype=eventtype,
        state=state,
        path=path
    }
end

local function dissectWatchEvent(buf, pkt, tree)
    local offset, watchevent = parseWatchEvent(buf)
    pkt.cols.info:set("WATCH EVENT")
    tree:append_text(
        string.format(" [WATCH EVENT: %s]",
                      watchEventTypes[watchevent.eventtype:int()])
    )
    local t_zxid = tree:add(f_zxid, watchevent.result.zxid)
    t_zxid:add(f_zxid_epoch, watchevent.result.zxid(0, 4))
    t_zxid:add(f_zxid_count, watchevent.result.zxid(4, 4))
    tree:add(f_err, watchevent.result.err)
    tree:add(f_eventtype, watchevent.eventtype)
    tree:add(f_state, watchevent.state)
    tree:add(f_path, watchevent.path)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- SETWATCHES

-- XXX: Untested!

local function parseSetWatchesRequest(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 4 > remain then return -1, nil end
    local dataw_num = buf(offset, 4)
    offset = offset + 4
    local dataw = {}
    for i = 0, dataw_num:uint() - 1 do
        local path_offset, path = parseString(buf(offset))
        if path_offset == -1 then return -1, nil end
        offset = offset + path_offset
        table:insert(dataw, path)
    end
    if offset + 4 > remain then return -1, nil end
    local existsw_num = buf(offset, 4)
    offset = offset + 4
    local existsw = {}
    for i = 0, existsw_num:uint() - 1 do
        local path_offset, path = parseString(buf(offset))
        if path_offset == -1 then return -1, nil end
        offset = offset + path_offset
        table:insert(existsw, path)
    end
    if offset + 4 > remain then return -1, nil end
    local childw_num = buf(offset, 4)
    offset = offset + 4
    local childw = {}
    for i = 0, childw_num:uint() - 1 do
        local path_offset, path = parseString(buf(offset))
        if path_offset == -1 then return -1, nil end
        offset = offset + path_offset
        table:insert(childw, path)
    end

    return offset, {
        dataw_num=dataw_num,
        dataw=dataw,
        existsw_num=existsw_num,
        existsw=existsw,
        childw_num=childw_num,
        childw=childw,
    }
end

local function reprSetWatchesRequest(setwatches_req, tree)
    t_dataw = tree:add(f_op) -- "Data Watches"
    t_dataw:add(f_count, setwatches_req.dataw_num)
    for i, path in ipairs(setwatches_req.dataw) do
        t_dataw:add(f_path, path)
    end
    t_existsw = tree:add(f_op) -- "Exists Watches"
    t_existsw:add(f_count, setwatches_req.existsw_num)
    for i, path in ipairs(setwatches_req.existsw) do
        t_existsw:add(f_path, path)
    end
    t_childw = tree:add(f_op) -- "Children Watches"
    t_childw:add(f_count, setwatches_req.childw_num)
    for i, path in ipairs(setwatches_req.childw) do
        t_childw:add(f_path, path)
    end
end

local function dissectSetWatchesRequest(buf, pkt, tree, _state)
    local offset, setwatches_req = parseSetWatchesRequest(buf)
    if offset == -1 then return false end
    pkt.cols.info:set("SETWATCHES REQUEST")
    tree:append_text(" [SETWATCHES REQUEST]")
    reprSetWatchesRequest(setwatches_req, tree)
    return DissRes.Client
end

------------------------------------------------------------------------------
-- AUTH

local function parseSetAuthRequest(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 4 > remain then return -1, nil end
    local authtype = buf(offset, 4)
    offset = offset + 4
    local scheme_offset, scheme = parseString(buf(offset))
    if scheme_offset == -1 then return -1, nil end
    offset = offset + scheme_offset
    local credential_offset, credential = parseString(buf(offset))
    if credential_offset == -1 then return -1, nil end
    offset = offset + credential_offset

    return offset, {
        authtype=authtype,
        scheme=scheme,
        credential=credential
    }
end

local function reprSetAuthRequest(setauth_req, tree)
    tree:add(f_authtype, setauth_req.authtype)
    tree:add(f_scheme, setauth_req.scheme)
    tree:add(f_credential, setauth_req.credential)
end

local parseAuthReqOpCode = {
    [100] = parseSetAuthRequest,
}

local reprAuthReqOpCode = {
    [100] = reprSetAuthRequest,
}

local function parseAuthRequest(buf)
    local offset = 0
    local remain = buf:len()

    if offset + 4 > remain then return -1, nil end
    local opcode = buf(offset, 4)
    offset = offset + 4

    local req_parse_fun = parseAuthReqOpCode[opcode:int()]
    if req_parse_fun == nil then return -1, nil end

    local authdata_offset, authdata = req_parse_fun(buf(offset))
    if authdata_offset == -1 then return -1, nil end
    offset = offset + authdata_offset

    return offset, {
        opcode=opcode,
        authdata=authdata
    }
end

local function dissectAuthRequest(buf, pkt, tree, _state)
    local offset, auth_req = parseAuthRequest(buf)
    if offset == -1 then return false end

    pkt.cols.info:set("AUTH REQUEST")
    tree:append_text(" [AUTH REQ]")
    tree:add(f_opCode, auth_req.opcode)
    local req_repr_fun = reprAuthReqOpCode[auth_req.opcode:int()]
    if req_repr_fun == nil then
        tree:add(f_data, auth_req.authdata)
    else
        req_repr_fun(auth_req.authdata, tree)
    end
    return DissRes.Client
end

local function parseAuthReply(buf)
    local offset = 0

    local result_offset, result = parseResult(buf(offset))
    if result_offset == -1 then return false end
    offset = offset + result_offset

    return offset, {
        result=result,
    }
end

local function dissectAuthReply(buf, pkt, tree, _state)
    local offset, auth_rep = parseAuthReply(buf)
    if offset == -1 then return false end

    pkt.cols.info:set("AUTH REPLY")
    tree:append_text(" [AUTH REP]")

    reprResult(auth_rep.result, tree)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- CONNECT

local function parseConnectRequest(buf)
    local offset = 0
    local remain = buf:len()
    if offset + 4 > remain then return -1, nil end
    local protoversion = buf(offset, 4)
    offset = offset + 4
    if offset + 8 > remain then return -1, nil end
    local zxid = buf(offset, 8)
    offset = offset + 8
    if offset + 4 > remain then return -1, nil end
    local timeout = buf(offset, 4)
    offset = offset + 4
    if offset + 8 > remain then return -1, nil end
    local session = buf(offset, 8)
    offset = offset + 8
    local passwd_offset, passwd = parseString(buf(offset))
    if passwd_offset == -1 then return -1, nil end
    offset = offset + passwd_offset
    if offset + 1 > remain then return -1, nil end
    local readonly = buf(offset, 1)
    offset = offset + 1

    return offset, {
        protoversion=protoversion,
        zxid=zxid,
        timeout=timeout,
        session=session,
        passwd=passwd,
        readonly=readonly,
    }
end

local function dissectConnectRequest(buf, pkt, tree)
    local offset, conn_req = parseConnectRequest(buf)
    if offset == -1 then return false end
    pkt.cols.info:set("CONNECT REQUEST")
    tree:append_text(" [CONNECT REQ]")
    tree:add(f_protoversion, conn_req.protoversion)
    tree:add(f_zxid, conn_req.zxid)
    tree:add(f_timeout, conn_req.timeout)
    tree:add(f_session, conn_req.session)
    tree:add(f_passwd, conn_req.passwd)
    tree:add(f_readonly, conn_req.readonly)
    return DissRes.Client
end

local function parseConnectReply(buf)
    local offset = 0
    local remain = buf:len()
    if offset + 4 > remain then return -1, nil end
    local protoversion = buf(offset, 4)
    offset = offset + 4
    if offset + 4 > remain then return -1, nil end
    local timeout = buf(offset, 4)
    offset = offset + 4
    if offset + 8 > remain then return -1, nil end
    local session = buf(offset, 8)
    offset = offset + 8
    local passwd_offset, passwd = parseString(buf(offset))
    if passwd_offset == -1 then return -1, nil end
    offset = offset + passwd_offset
    if offset + 1 > remain then return -1, nil end
    local readonly = buf(offset, 1)
    offset = offset + 1

    return offset, {
        protoversion=protoversion,
        timeout=timeout,
        session=session,
        passwd=passwd,
        readonly=readonly,
    }
end

local function dissectConnectReply(buf, pkt, tree)
    local offset, conn_rep = parseConnectReply(buf)
    if offset == -1 then return false end
    pkt.cols.info:set("CONNECT REPLY")
    tree:append_text(" [CONNECT REP]")
    tree:add(f_protoversion, conn_rep.protoversion)
    tree:add(f_timeout, conn_rep.timeout)
    tree:add(f_session, conn_rep.session)
    tree:add(f_passwd, conn_rep.passwd)
    tree:add(f_readonly, conn_rep.readonly)
    return DissRes.Server
end

------------------------------------------------------------------------------
-- PING

local function dissectPingRequest(buf, pkt, tree)
    tree:append_text(" [PING]")
    if buf:len() ~= 4 then return false end
    tree:add(f_opCode, buf(0, 4))
    return DissRes.Client
end

local function dissectPingReply(buf, pkt, tree)
    tree:append_text(" [PING REP]")
    if buf:len() ~= 12 then return false end
    -- XXX: Parse ping reply payload
    tree:add(f_data, buf(0, 12))
    return DissRes.Server
end

------------------------------------------------------------------------------
-- Special XID dispatcher
local dissectReqXID = {
    [0] = dissectConnectRequest,
    [-2] = dissectPingRequest,
    [-4] = dissectAuthRequest,
    [-8] = dissectSetWatchesRequest,
}

local dissectRepXID = {
    [0] = dissectConnectReply,
    [-1] = dissectWatchEvent,
    [-2] = dissectPingReply,
    [-4] = dissectAuthReply,
}

local function dispatchXIDDissector(buf, pkt, tree, state, xid)
    -- print("xid", xid)
    if state.dir == Direction.Client2Server then
        return dispatch(dissectReqXID, xid)(buf, pkt, tree)
    elseif state.dir == Direction.Server2Client then
        return dispatch(dissectRepXID, xid)(buf, pkt, tree)
    elseif state.dir == nil then
        -- Try to parse as client packet then as server packet
        local res = dispatch(dissectReqXID, xid)(buf, pkt, tree)
        if res == false then
            res = dispatch(dissectRepXID, xid)(buf, pkt, tree)
        end
        return res
    end
end

------------------------------------------------------------------------------
local function dissect(buf, pkt, tree, state)
    local offset = 0
    local remain = buf:len()

    -- We need at list 8 bytes for len+xid
    if offset + 8 > remain then return false end

    tree:add(f_len, buf(offset, 4))
    offset = offset + 4
    local xidBuf = buf(offset, 4)
    local xid = xidBuf:int()
    if xid <= 0 then
        if FIXED_XIDS[xid] == nil then return false end
        -- NOTE: CONNECT packet starts *on* the xid, so for those, do not
        -- extract field/update offset
        if xid ~= 0 then
            tree:add(f_xid, xidBuf)
            offset = offset + 4
        end
        return dispatchXIDDissector(buf(offset), pkt, tree, state, xid)
    else
        -- Regular operation
        tree:add(f_xid, xidBuf)
        offset = offset + 4
        local opCode
        if state.dir == Direction.Client2Server then
            -- New request, record the opCode
            local opCodeBuf = buf(offset, 4)
            tree:add(f_opCode, opCodeBuf)
            offset = offset + 4
            -- record the opCode
            opCode = opCodeBuf:int()
            state.xids[xid] = opCode
            tree:append_text(string.format(" [%s]", opCodes[opCode]))
        elseif state.dir == Direction.Server2Client then
            -- Reply, read return status
            opCode = state.xids[xid]
            -- print("opCode", opCode)
            if opCode ~= nil then
                -- state.xids[xid] = nil
                tree:add(f_opCode, xidBuf, opCode) -- XXX.set_generated()
                tree:append_text(string.format(" [%s REP]", opCodes[opCode]))
            end
            local result_offset, result = parseResult(buf(offset))
            if result_offset == -1 then return false end
            offset = offset + result_offset
            reprResult(result, tree)
        else
            -- We don't know the direction.
            return false
        end
        if offset == remain then return state.dir end
        -- check if we know about this XID
        if opCode == nil then
            -- We don't know about this request, dump the payload
            tree:add(f_data, buf(offset))
            return DissRes.Server
        else
            return dispatchOpCodeDissector(buf(offset), pkt, tree, state, opCode)
        end
    end
end

local function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

------------------------------------------------------------------------------
ZabProto = Proto("ZAB", "ZAB 1.0")

local default_settings = {
    port = DEFAULT_ZAB_PORT -- Since a client may talk to many servers, on different ports, this should be the client port
}

ZabProto.prefs.port  = Pref.uint(
    "Port number",
    default_settings.port,
    "The TCP port number for ZAB"
)


ZabProto.fields = {
    f_pkt, f_op, -- Structural fields
    f_4lw, f_len, f_xid, f_data, f_opCode, f_path, f_watch, f_protoversion,
    f_zxid, f_zxid_epoch, f_zxid_count, f_timeout, f_session, f_authtype,
    f_perms, f_scheme, f_credential, f_datalength, f_flags, f_ephemeral,
    f_sequence, f_container, f_ttl, f_joining, f_leaving, f_newmembers,
    f_config_id, f_done, f_err, f_version, f_eventtype, f_state, f_passwd,
    f_readonly, f_count, f_child, f_czxid, f_czxid_epoch, f_czxid_count,
    f_mzxid, f_mzxid_epoch, f_mzxid_count, f_ctime, f_mtime, f_cversion,
    f_aversion, f_ephemeralowner, f_numchildren, f_pzxid, f_pzxid_epoch,
    f_pzxid_count
}

function ZabProto.dissector(buf, pkt, root)
    if buf:reported_len() > buf:len() then
        -- Truncated capture, ignore
        pkt.cols.info:set("TRUNCATED")
        return 0
    end

    pkt.cols.protocol = ZabProto.name
    local tree = root:add(ZabProto, buf())

    -- Memorize the sender/recipient to categorize below
    local sender = string.format("%s:%s", pkt.src, pkt.src_port)
    local recipient = string.format("%s:%s", pkt.dst, pkt.dst_port)

    local state = {sender=sender, recipient=recipient, dir=nil, xids=nil}
    if CLIENTS[sender] ~= nil then
        state.xids = CLIENTS[sender]
        state.dir = Direction.Client2Server
    elseif CLIENTS[recipient] ~= nil then
        state.xids = CLIENTS[recipient]
        state.dir = Direction.Server2Client
    end

    -- Handle fragmentation or combining of packets
    -- https://wiki.wireshark.org/Lua/Dissectors#TCP_reassembly
    local res = nil
    local start_offset = 0 -- current start of a packet
    local remain = buf:len()

    -- Handle multiple ZK packets in the TVB
    repeat
        local offset = start_offset

        if (remain - offset) < 4 then
            -- Didn't get enough to even read a length
            -- Ask Wireshard for more data
            -- print("Fragmented, too small", remain)
            pkt.desegment_offset = 0
            pkt.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end

        local packet_length = buf(offset, 4):uint()
        offset = offset + 4
        -- print("Debug", start_offset, packet_length, offset, remain)
        if packet_length >= 1094795585 then
            -- Looks like plain text.
            -- This is 'AAAA' as int (or a length of about 1GB)
            packet_length = remain -- 4lw eats the whole packet
            local pktBuf = buf(start_offset)
            local t_pkt = tree:add(f_pkt,  pktBuf)
            res = dissect4lw(pktBuf, pkt, t_pkt)

        elseif packet_length > (remain - offset) then
            pkt.desegment_offset = start_offset -- restart @ packet start
            pkt.desegment_len = packet_length - (remain - offset) 
            -- print("Fragmented", pkt.desegment_offset, pkt.desegment_len)
            return

        else -- packet_length <= buf:len()
            -- We can parse at least one packet, from start_offset, [length, packet]
            local pktBuf = buf(start_offset, 4 + packet_length)
            local t_pkt = tree:add(f_pkt, pktBuf)
            res = dissect(pktBuf, pkt, t_pkt, state)
        end

        if res == false then
            -- Dissect failed
            -- print("FAIL")
            return 0
        elseif res == DissRes.Client then
            -- Keep a hash of XIDs for that client
            if CLIENTS[sender] == nil then
                -- print("NEW CLIENT", sender)
                CLIENTS[sender] = {}
            end
        elseif res == DissRes.Server then
            if CLIENTS[recipient] == nil then
                -- print("NEW CLIENT", recipient)
                CLIENTS[recipient] = {}
            end
        else -- res == true
            -- Nothing to do?
        end
        -- Move forward by a packet_len field + the packet length
        start_offset = start_offset + 4 + packet_length

        -- Did we reach the end?
    until start_offset == remain

    -- print("State:", dump(CLIENTS))
end

----------------------------------------
-- a function for handling prefs being changed
function ZabProto.prefs_changed()
    if default_settings.port ~= ZabProto.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):remove(default_settings.port, ZabProto)
        end
        -- set our new default
        default_settings.port = ZabProto.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            DissectorTable.get("tcp.port"):add(default_settings.port, ZabProto)
        end
    end

end

function ZabProto.init()
    local tcp_dissector_table = DissectorTable.get("tcp.port")
    tcp_dissector_table:add_for_decode_as(ZabProto)
    tcp_dissector_table:add(default_settings.port, ZabProto)
end

----------------------------------------
-- for testing purposes, we want to be able to pass in changes to the defaults
-- from the command line; because you can't set lua preferences from the command
-- line using the '-o' switch (the preferences don't exist until this script is
-- loaded, so the command line thinks they're invalid preferences being set)
-- so we pass them in as command arguments instead, and handle it here:
local args={...} -- get passed-in args
if args and #args > 0 then
    for _, arg in ipairs(args) do
        local name, value = arg:match("(.+)=(.+)")
        if name and value then
            if tonumber(value) then
                value = tonumber(value)
            else
                error("invalid commandline argument value")
            end
            default_settings[name] = value
        end
    end
end
