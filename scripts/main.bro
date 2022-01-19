##! Zeek script is used to detect potentially defaced or compromised HTTP sites containing generic pharmacy references.

@load base/utils/site
@load base/frameworks/notice

module HTTPDetectPharm;

export {

        redef enum Notice::Type += {
                ## Generated if a site is found containing pharmacy references
                Found
        };

        # Although defacements & blackhat seo has a variety of content, these tend
        # to show up in a large percentage of pharmacy defacements.
        const pharm_sigs = /([[:space:]]+)cialis([[:space:]]+)/i |
                           /([[:space:]]+)viagra([[:space:]]+)/i |
                           /([[:space:]]+)cheap[:space:]pills([[:space:]]+)/i |
                           /([[:space:]]+)prescription[:space:]drugs([[:space:]]+)/i &redef;
}

global pharm_http_success_status_codes: set[count] = {
        200,
        201,
        202,
        203,
        204,
        205,
        206,
        207,
        208,
        226,
        304
};

# TODO: File extracted discovered sites

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
        if(Site::is_local_addr(c$id$resp_h) &&
           c$http?$status_code &&
           c$http$status_code in HTTPDetectPharm::pharm_http_success_status_codes &&
           pharm_sigs in data)
        {
                # Check for field existence and assign defaults
                local respHost = c$http?$host ? c$http$host : cat(c$id$resp_h);
                local method = c$http?$method ? c$http$method : "UNKNOWN";
                local uri = c$http?$uri ? c$http$uri : "UNKNOWN";
                NOTICE([$note=Found,
                        $msg=fmt("HTTP payload of website contains references to pharmacy info - Response: %s %s - URL: %s%s", c$http$status_code, method, respHost, uri),
                        $sub=fmt("%s", data),
                        $conn=c,
                        $identifier=cat(c$id$resp_h, uri),
                        $suppress_for=1day]);

        }
}
