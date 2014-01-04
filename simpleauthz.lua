local groups = {}
local rule_actions = {}
local rule_roles = {}
local rule_except_roles = {}

local function expand_roles (roles)
    -- recursively expand list of group names and uids to a list of pure uids
    local ret = {}
    for k, v in pairs(roles) do
        if type(k) == "string" then
            name = k
        else
            name = v
        end
        if string.sub(name, 1, 1) == "@" then
            local group_name = string.sub(name, 2, string.len(name))
            local group_roles = groups[group_name]
            if group_roles ~= nil then
                for _name, _ in pairs(expand_roles(group_roles)) do
                    ret[_name] = true
                end
            end
        else
            ret[name] = true
        end
    end
    return ret
end

local function create_group (group_name, ...)
    -- create a group of uids

    groups[group_name] = expand_roles({...})
end

local function create_rule (rule_name, action, roles, except_roles)
    -- create a rule
    -- 'action': can be 'allow' or 'deny'
    -- 'roles': list of uids and group_names
    -- uid or group listed in 'roles' will be 'action'ed, unless the uid is listed in 'except_roles'.

    rule_roles[rule_name] = expand_roles(roles)
    rule_except_roles[rule_name] = expand_roles(except_roles)
    rule_actions[rule_name] = (action == "allow")
end

local function access (rule_name, uid)
    -- do authz process, be invoked by access_by_lua:
    --   access_by_lua 'simpleauthz.auth(rule_name, uid)';

    if uid == nil then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    action = rule_actions[rule_name]
    roles = rule_roles[rule_name]
    except_roles = rule_except_roles[rule_name]

    -- by default , if the rule_name does not exist, forbid access
    if action == nil or roles == nil or except_roles == '' then
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end

    if action then
        -- rule action == "allow"
        if roles[uid] and not except_roles[uid] then
            return
        end
        ngx.exit(ngx.HTTP_FORBIDDEN)
    else
        -- rule action == "deny"
        if roles[uid] and not except_roles[uid] then
            ngx.exit(ngx.HTTP_FORBIDDEN)
        end
        return
    end
end

local function access_with_authn(rule_name, get_uid, auth_url, ...)
    uid = get_uid(...)

    if uid == nil then
        -- need authn
        ngx.header['Location'] = auth_url
        ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
    end

    -- authn successed
    return access(rule_name, uid)
end

-- special rules to allow/deny all (logged in) users
create_rule ('ALLOW_ALL', 'deny', {}, {})
create_rule ('DENY_ALL', 'allow', {}, {})

local P = {
    create_group = create_group,
    create_rule = create_rule,
    access = access,
    access_with_authn = access_with_authn
}

return P
