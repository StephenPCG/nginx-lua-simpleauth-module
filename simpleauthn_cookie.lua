local secret_key = 'please call simpleauthn.set_secret_key() to change this key!'
local max_age = 60 * 60 * 24
local auth_url_fmt = '/auth/?%s'
local hash_func = ngx.md5

local function set_secret_key (key)
    secret_key = key
end

local function set_max_age (age_in_seconds)
    max_age = age_in_seconds
end

local function set_auth_url_fmt (fmt)
    auth_url_fmt = fmt
end

local function set_hash_func (func)
    hash_func = func
end

local function calc_hash(uid, expire, ...)
    hashdata = secret_key .. '|' .. uid .. '|' .. expire .. '|'
    for _, k in pairs({...}) do
        hashdata = hashdata .. k .. '|'
    end
    return hash_func(hashdata)
end

local function set_cookie (uid, domain, ...)
    -- on successfully authenticated, call this function to set cookie

    expire = ngx.req.start_time() + max_age

    hash = calc_hash(uid, expire, ...)

    postfix = "; Domain=" .. domain .. "; Path=/; Max-Age=" .. max_age
    ngx.header["Set-Cookie"] = {
        "authn_uid=" .. uid .. postfix,
        "authn_hash=" .. hash .. postfix,
        "authn_expire=" .. expire .. postfix,
    }

    if ngx.var.arg_next then
        return ngx.redirect(ngx.unescape_uri(ngx.var.arg_next), ngx.HTTP_MOVED_TEMPORARILY)
    end
end

local function get_uid (...)
    -- call this function to get authenticated uid, if not authenticated, return nil

    uid = ngx.var.cookie_authn_uid
    hash = ngx.var.cookie_authn_hash
    expire = ngx.var.cookie_authn_expire

    if uid ~= nil and hash ~= nil and expire ~= nil and
        ngx.req.start_time() < tonumber(expire) and
        hash == calc_hash(uid, expire, ...) then
            return uid
    end

    return nil
end

local function get_current_url ()
    return ngx.escape_uri(ngx.var.scheme .. "://" .. ngx.var.http_host .. ngx.var.request_uri)
end

local function get_auth_url ()
    return string.format(auth_url_fmt, "next=" .. get_current_url())
end

local function access (...)
    uid = get_uid(...)
    if uid == nil then
        ngx.header['Location'] = get_auth_url()
        ngx.exit(ngx.HTTP_MOVED_TEMPORARILY)
    end
end

local P = {
    set_secret_key = set_secret_key,
    set_max_age = set_max_age,
    set_cookie = set_cookie,
    set_auth_url_fmt = set_auth_url_fmt,
    set_hash_func = set_hash_func,
    get_auth_url = get_auth_url,
    get_uid = get_uid,
    access = access
}

return P
