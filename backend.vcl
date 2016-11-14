## Backends
backend default {
    .host = "localhost";
    .port = "80";
    .first_byte_timeout = 300s;
    .between_bytes_timeout = 30s;
}

## IPs allowed for purging cache
acl cache_acl {
    # dev
    "127.0.0.1";
}

####################################
# HTTP request enters the Varnish
####################################
sub vcl_recv {

    # Backends
    if(server.ip == "localhost") {
      set req.backend = default;
    }

    # Restricted processing for purging cache
    if (client.ip ~ cache_acl) {
        # BAN requests
        if (req.request == "BAN") {
            if(req.http.X-Tags) {
                ban("obj.http.X-Tags ~ " + req.http.X-Tags);
            }
            if(req.http.X-Url) {
                ban("obj.http.X-Url ~ " + req.http.X-Url);
            }
            error 200 "Banned";
        }

        # Convert to a PURGE
        if (req.http.Cache-Control == "no-cache") {
            remove req.http.Cache-Control;
            set req.request = "PURGE";
        }

        // PURGE requests are handled in hit/miss
        if (req.request == "PURGE") {
            return(lookup);
        }
    }

    ## any unusual requests are passed through.
    if (req.request != "GET" && req.request != "HEAD" && req.request != "PUT" && req.request != "POST" && req.request != "TRACE" && req.request != "OPTIONS" && req.request != "DELETE") {
        return (pipe);
    }

   if (req.request == "POST") {
         return (pipe);
   }

    ## Varnish should just take care of GET and HEAD requests, all other requests are passed
    if (req.request != "GET" && req.request != "HEAD") {
        return (pass);
    }

    ## additional safety check for a few url's
    if (req.url ~ ".*(admin|checkout|customer|account|feed|wishlist|form_key|uenc|datatrans|aoestatic\/call).*") {
        return (pass);
    }

    # Remove cookie for known-static file extensions
    if (req.url ~ "\.(txt|xml|gif|jpg|swf|css|js|png|jpeg|tiff|tif|svg|ttf|swf|ico|vsd|doc|ppt|pps|xls|mp3|mp4|m4a|ogg|mov|avi|wmv|sxw|zip|gz|bz2|tgz|tar|rar|eot|woff2|woff)$" ) {
        remove req.http.Cookie;
    }

    ## exclude caching for admins
    if (req.http.Cookie ~ ".*(admin).*") {
        return (pass);
    }

    # exclude for specific store cookie
    if (req.http.Cookie ~ "(^|;\s*)(store)=[^;]*") {
        return (pass);
    }

    # exclude for specific scenarios like add to cart
    if (req.http.Cookie ~ ".*(frontend|numberofitemsincart|isloggedin=1).*") {
        return (pass);
    }

    ## if we have an authorization or authentication header, we definitely do not want to cache
    if (req.http.Authenticate || req.http.Authorization) {
      return(pass);
    }

    # store original url in extra header field
    set req.http.X-Original-Url = req.url;

    # handle google bot requests, especially google shopping stuff
    set req.url = regsuball(req.url, "\?(utm_[^=&]*=[^&=]*&?)+", "?");
    set req.url = regsuball(req.url, "&(utm_[^=&]*=[^&=]*(&|$))+", "\2");
    set req.url = regsuball(req.url, "\?(\d+=[^&=]*&?)+", "?");
    set req.url = regsuball(req.url, "&(\d+=[^&=]*(&|$))+", "\2");
    set req.url = regsuball(req.url, "\?(_escaped_fragment_=[^&=]*&?)+", "?");
    set req.url = regsuball(req.url, "&(_escaped_fragment_=[^&=]*(&|$))+", "\2");
    set req.url = regsuball(req.url, "\?(gclid=[^&=]*&?)+", "?");
    set req.url = regsuball(req.url, "&(gclid=[^&=]*(&|$))+", "\2");
    set req.url = regsuball(req.url, "\?(SID=[^&=]*&?)+", "?");
    set req.url = regsuball(req.url, "&(SID=[^&=]*(&|$))+", "\2");
    set req.url = regsuball(req.url, "\?(___store=[^&=]*&?)+", "?");
    set req.url = regsuball(req.url, "&(___store=[^&=]*(&|$))+", "\2");
    set req.url = regsuball(req.url, "\?(m=[^&=]*&?)+", "?");
    set req.url = regsuball(req.url, "&(m=[^&=]*(&|$))+", "\2");
    set req.url = regsub(req.url, "\?&?=?&?$", "");


    ## if no rule matches, we lookup the item in the cache
    return(lookup);
}

####################################
# HTTP response fetched from backend
####################################
sub vcl_fetch {
    # set minimum timeouts to auto-discard stored objects
    set beresp.grace = 600s;

    # Add URL used for PURGE
    set beresp.http.X-Url = req.url;

    # special 404 cases
    if (beresp.status == 404) {
        remove beresp.http.Set-Cookie;
        remove beresp.http.Age;
        remove beresp.http.Pragma;
        set beresp.http.Cache-Control = "public";
        set beresp.grace = 5m;
        set beresp.ttl = 5m;

        if (req.url ~ "\.(txt|xml|gif|jpg|swf|css|js|png|jpeg|tiff|tif|svg|ttf|swf|ico|vsd|doc|ppt|pps|xls|mp3|mp4|m4a|ogg|mov|avi|wmv|sxw|zip|gz|bz2|tgz|tar|rar|eot|woff2|woff)$" ) {
            set beresp.http.X-Aoestatic-Fetch = "STATIC | 404";
        } else {
            set beresp.http.X-Aoestatic-Fetch = "PHP | 404";
        }

        return(deliver);
    }

    if (beresp.http.X-Aoestatic == "cache") {
        # Cacheable object as indicated by backend response
        remove beresp.http.Set-Cookie;
        remove beresp.http.Age;
        remove beresp.http.Pragma;
        set beresp.http.Cache-Control = "public";
        set beresp.grace = 3d;
        set beresp.ttl = 3d;
        set beresp.http.X-Aoestatic-Fetch = "PHP | Removed cookie in vcl_fetch";
    } else if (req.url ~ "\.(txt|xml|gif|jpg|swf|css|js|png|jpeg|tiff|tif|svg|ttf|swf|ico|vsd|doc|ppt|pps|xls|mp3|mp4|m4a|ogg|mov|avi|wmv|sxw|zip|gz|bz2|tgz|tar|rar|eot|woff2|woff)$" ) {
        remove beresp.http.Set-Cookie;
        remove beresp.http.Age;
        remove beresp.http.Pragma;
        set beresp.http.Cache-Control = "public";
        set beresp.grace = 3d;
        set beresp.ttl = 3d;
        set beresp.http.X-Tags = "STATIC";
        set beresp.http.X-Aoestatic-Fetch = "STATIC | Removed cookie in vcl_fetch";
    }

    if (beresp.status >= 300 && beresp.status < 400 && req.url ~ "\.(txt|xml|gif|jpg|swf|css|js|png|jpeg|tiff|tif|svg|ttf|swf|ico|vsd|doc|ppt|pps|xls|mp3|mp4|m4a|ogg|mov|avi|wmv|sxw|zip|gz|bz2|tgz|tar|rar|eot|woff2|woff)$" ) {
        set beresp.grace = 1h;
        set beresp.ttl = 1h;
        set beresp.http.X-Aoestatic-Fetch = "STATIC | Status between 300 and 400";
    } else if (beresp.status >= 300) {
        # Don't cache redirects and negative lookups
        set beresp.http.X-Aoestatic-Pass = "Status greater than 300";
        set beresp.ttl = 0s;
    } else if (beresp.ttl <= 0s) {
        set beresp.http.X-Aoestatic-Pass = "Not cacheable";
        set beresp.ttl = 0s;

        return(hit_for_pass);
    } else if (beresp.http.Set-Cookie) {
        set beresp.http.X-Aoestatic-Pass = "Cookie";
        set beresp.ttl = 0s;
    } else if (!beresp.http.Cache-Control ~ "public") {
        set beresp.http.X-Aoestatic-Pass = "Cache-Control is not public";
        set beresp.ttl = 0s;
    } else if (beresp.http.Pragma ~ "(no-cache|private)") {
        set beresp.http.X-Aoestatic-Pass = "Pragma is no-cache or private";
        set beresp.ttl = 0s;
    }
}

####################################
# HTTP response is delivered to the visitor
####################################
sub vcl_deliver {
    if (req.url !~ "^[^?]+\.(txt|xml|gif|jpg|swf|css|js|png|jpeg|tiff|tif|svg|ttf|swf|ico|vsd|doc|ppt|pps|xls|mp3|mp4|m4a|ogg|mov|avi|wmv|sxw|zip|gz|bz2|tgz|tar|rar|eot|woff2|woff)(\?.*)?$") {
        set resp.http.Cache-Control = "no-cache, no-store, must-revalidate";
        set resp.http.Pragma = "no-cache";
        set resp.http.Expires = "0";
        set resp.http.Age = "0";
    }

    if (obj.hits > 0) {
        set resp.http.X-Cache = "HIT";
        set resp.http.X-Cache-Hits = obj.hits;
    } else {
        set resp.http.X-Cache = "MISS";
    }

    if (resp.http.X-Aoestatic-Debug != "true") {
        # Remove internal headers
        # remove resp.http.Via;
        remove resp.http.Server;
        remove resp.http.X-Powered-By;
        remove resp.http.X-Varnish;
        remove resp.http.X-Url;
        remove resp.http.X-Tags;
        remove resp.http.X-Aoestatic;
        remove resp.http.X-Aoestatic-Debug;
        remove resp.http.X-Aoestatic-Fetch;
        remove resp.http.X-Aoestatic-Pass;
        remove resp.http.X-Aoestatic-Action;
        remove resp.http.X-Aoestatic-Lifetime;
    }
}

sub vcl_pipe {

  # make sure we have the correct ip in x-forwarded-for
  if (req.http.X-Forwarded-For) {
    set bereq.http.X-Forwarded-For = req.http.X-Forwarded-For;
  }
  else {
    set bereq.http.X-Forwarded-For = regsub(client.ip, ":.*", "");
  }

  # http://www.varnish-cache.org/ticket/451
  # This forces every pipe request to be the first one.
  set bereq.http.connection = "close";
}

sub vcl_pass {

  # make sure we have the correct ip in x-forwarded-for
  if (req.http.X-Forwarded-For) {
    set bereq.http.X-Forwarded-For = req.http.X-Forwarded-For;
  }
  else {
    set bereq.http.X-Forwarded-For = regsub(client.ip, ":.*", "");
  }

}

sub vcl_miss {

  # make sure we have the correct ip in x-forwarded-for
  if (req.http.X-Forwarded-For) {
    set bereq.http.X-Forwarded-For = req.http.X-Forwarded-For;
  }
  else {
    set bereq.http.X-Forwarded-For = regsub(client.ip, ":.*", "");
  }

  if (req.request == "PURGE") {
    purge;
    error 200 "Purged";
  }

}

sub vcl_hit {

  # purge request
  if (req.request == "PURGE") {
    purge;
    error 200 "Purged";
  }

}