%%%-------------------------------------------------------------------
%%% @author lesliechou lesliechou7@outlook.com
%%% @doc
%%% Qcloud cos sts service interface module.
%%% @end
%%%-------------------------------------------------------------------
-module(cos_sts).
-author("lesliechou").

-export([init/1, get_credential/1]).

-define(sts_url, "https://sts.tencentcloudapi.com/").
-define(sts_domain, "sts.tencentcloudapi.com").

-record(sts, {
    secret_id, secret_key, duration_seconds, bucket, region, resource,
    allow_actions, policy, network_proxy, url, domain
}).

%% @doc Init the client config.
-spec init(map()) -> #sts{} | {error, Reason :: term()}.
init(Config) when is_map(Config) ->
    InitOpts = [
        secret_id, secret_key, duration_seconds, bucket, region,
        resource, allow_actions, policy, network_proxy, url, domain
    ],
    init(InitOpts, Config, #sts{}).

init([secret_id | T], Config, Sts) ->
    case maps:get(secret_id, Config, "") of
        SecretId when is_list(SecretId) ->
            init(T, Config, Sts#sts{secret_id = SecretId});
        _ ->
            {error, {bad_value, secret_id}}
    end;
init([secret_key | T], Config, Sts) ->
    case maps:get(secret_key, Config, "") of
        SecretKey when is_list(SecretKey) ->
            init(T, Config, Sts#sts{secret_key = SecretKey});
        _ ->
            {error, {bad_value, secret_key}}
    end;
init([duration_seconds | T], Config, Sts) ->
    case maps:get(duration_seconds, Config, 1800) of
        DurationSeconds when is_integer(DurationSeconds) ->
            init(T, Config, Sts#sts{duration_seconds = DurationSeconds});
        _ ->
            {error, {bad_value, duration_seconds}}
    end;
init([bucket | T], Config, Sts) ->
    case maps:get(bucket, Config, "") of
        Bucket when is_list(Bucket) ->
            init(T, Config, Sts#sts{bucket = Bucket});
        _ ->
            {error, {bad_value, bucket}}
    end;
init([region | T], Config, Sts) ->
    case maps:get(region, Config, "") of
        Region when is_list(Region) ->
            init(T, Config, Sts#sts{region = Region});
        _ ->
            {error, {bad_value, region}}
    end;
init([resource | T], Config, Sts) ->
    case maps:get(resource, Config, "") of
        Recource when is_list(Recource) ->
            init(T, Config, Sts#sts{resource = Recource});
        _ ->
            {error, {bad_value, resource}}
    end;
init([allow_actions | T], Config, Sts) ->
    case maps:get(allow_actions, Config, "") of
        AllowActions when is_list(AllowActions) ->
            init(T, Config, Sts#sts{allow_actions = AllowActions});
        _ ->
            {error, {bad_value, allow_actions}}
    end;
init([policy | T], Config, Sts) ->
    case maps:get(policy, Config, "") of
        Policy when is_list(Policy) ->
            init(T, Config, Sts#sts{policy = Policy});
        _ ->
            {error, {bad_value, policy}}
    end;
init([network_proxy | T], Config, Sts) ->
    case maps:get(network_proxy, Config, "") of
        NetworkProxy when is_list(NetworkProxy) ->
            init(T, Config, Sts#sts{network_proxy = NetworkProxy});
        _ ->
            {error, {bad_value, network_proxy}}
    end;
init([url | T], Config, Sts) ->
    case maps:get(url, Config, ?sts_url) of
        Url when is_list(Url) ->
            init(T, Config, Sts#sts{url = Url});
        _ ->
            {error, {bad_value, url}}
    end;
init([domain | T], Config, Sts) ->
    case maps:get(domain, Config, ?sts_domain) of
        Domain when is_list(Domain) ->
            init(T, Config, Sts#sts{domain = Domain});
        _ ->
            {error, {bad_value, domain}}
    end;
init([], Config, Sts) ->
    CheckOpts = [secret_id, secret_key, policy],
    check_sts(CheckOpts, Config, Sts).

check_sts([secret_id | T], Config, Sts) ->
    case Sts#sts.secret_id =/= "" of
        true ->
            check_sts(T, Config, Sts);
        false ->
            {error, {empty_value, secret_id}}
    end;
check_sts([secret_key | T], Config, Sts) ->
    case Sts#sts.secret_key =/= "" of
        true ->
            check_sts(T, Config, Sts);
        false ->
            {error, {empty_value, secret_key}}
    end;
check_sts([policy | T], Config, Sts) ->
    case Sts#sts.policy =/= "" of
        true ->
            check_sts(T, Config, Sts);
        false ->
            check_sts([region, bucket, resource_prefix | T], Config, Sts)
    end;
check_sts([region | T], Config, Sts) ->
    case Sts#sts.region =/= "" of
        true ->
            check_sts(T, Config, Sts);
        false ->
            {error, {empty_value, region}}
    end;
check_sts([bucket | T], Config, Sts) ->
    case Sts#sts.bucket =/= "" of
        true ->
            check_sts(T, Config, Sts);
        false ->
            {error, {empty_value, bucket}}
    end;
check_sts([resource_prefix | T], Config, Sts) ->
    case maps:get(resource_prefix, Config, "") of
        ResourcePrefix when is_list(ResourcePrefix) andalso ResourcePrefix =/= "" ->
            check_sts(T, Config, Sts);
        _ ->
            {error, {empty_value, resource_prefix}}
    end;
check_sts([], Config, Sts) ->
    case Sts#sts.policy of
        "" ->
            init_resource(Config, Sts);
        _ -> Sts
    end.

init_resource(Config, Sts) ->
    ResourcePrefix = [First | _] = maps:get(resource_prefix, Config),
    RealResourcePrefix = case First of
                             $/ -> ResourcePrefix;
                             _ ->
                                 [$/ | ResourcePrefix]
                         end,
    #sts{region = Region, bucket = Bucket} = Sts,
    try
        [_, String] = string:split(Bucket, "-", trailing),
        AppId = string:strip(String, both),
        Resource = lists:concat([
            "qcs::cos:", Region, ":uid/", AppId, ":", Bucket, RealResourcePrefix
        ]),
        Sts#sts{resource = Resource}
    catch
        _ : _ ->
            {error, {invalid_value, bucket}}
    end.

%% @doc Get credential from Qcloud cam.
-spec get_credential(#sts{}) -> map() | {error, Reason :: term()}.
get_credential(Sts) ->
    Policy = case Sts#sts.policy of
                 "" ->
                     [
                         {<<"version">>, <<"2.0">>},
                         {<<"statement">>, [
                             [
                                 {<<"action">>, [list_to_binary(Sts#sts.allow_actions)]},
                                 {<<"effect">>, <<"allow">>},
                                 {<<"resource">>, [list_to_binary(Sts#sts.resource)]}
                             ]
                         ]}
                     ];
                 _ ->
                     Sts#sts.policy
             end,
    PolicyEncode = jsx:encode(Policy),

    Now = timestamp(),
    Data = [
        {<<"Name">>, <<"cos-sts-erlang">>},
        {<<"Policy">>, PolicyEncode},
        {<<"DurationSeconds">>, Sts#sts.duration_seconds}
    ],
    Body = binary_to_list(jsx:encode(Data)),

    ContentType = "application/json",
    EncryptHeaders = [
        {"Content-Type", ContentType},
        {"Host", ?sts_domain}
    ],
    Sign = encrypt(Sts, "POST", EncryptHeaders, Body, Now),

    Method = post,
    Url = Sts#sts.url,
    Headers = EncryptHeaders ++ [
        {"Connection", "close"},
        {"X-TC-Action", "GetFederationToken"},
        {"X-TC-RequestClient", "APIExplorer"},
        {"X-TC-Timestamp", integer_to_list(Now)},
        {"X-TC-Version", "2018-08-13"},
        {"X-TC-Region", "ap-shanghai"},
        {"X-TC-Language", "zh-CN"},
        {"Authorization", Sign}
    ],
    HttpOpts = [{timeout, 5000}],
    Opts = [],

    try
        case httpc:request(Method, {Url, Headers, ContentType, Body}, HttpOpts, Opts) of
            {ok, {_, _, ResponseBody}} ->
                case jsx:decode(list_to_binary(ResponseBody)) of
                    Response when is_map(Response) ->
                        Response;
                    _ ->
                        {error, {json_decode_fail, ResponseBody}}
                end;
            {error, Reason} ->
                {error, Reason}
        end
    catch
        EType : EReason ->
            io:format("Get credential fail, error_type: ~w, reason: ~w~n", [EType, EReason]),
            {error, {EType, EReason}}
    end.

timestamp() ->
    {M, S, _} = os:timestamp(),
    M * 1000000 + S.

%% Calculate the signature using algorithm v3.
encrypt(Sts, HTTPRequestMethod, Headers, Body, RequestTimestamp) ->
    CanonicalURI = "/",
    CanonicalQueryString = "",
    {SignedHeadersList, CanonicalHeaders} = lists:foldr(
        fun({Key, Value}, {AccSignedHeadersList, AccCanonicalHeaders}) ->
            RealKey = string:to_lower(string:strip(Key, both)),
            NewAccSignedHeaders = [RealKey | AccSignedHeadersList],
            NewAccCanonicalHeaders =
                case is_list(Value) of
                    true ->
                        RealValue = string:to_lower(string:strip(Value, both)),
                        lists:concat([RealKey, ":", RealValue, "\n"]) ++ AccCanonicalHeaders;
                    false ->
                        lists:concat([RealKey, ":", Value, "\n"]) ++ AccCanonicalHeaders
                end,
            {NewAccSignedHeaders, NewAccCanonicalHeaders}
        end, {"", ""}, Headers),
    SignedHeaders = string:join(SignedHeadersList, ";"),
    HashedRequestPayload = binary_to_4bit_list(crypto:hash(sha256, Body)),
    CanonicalRequest = lists:concat([
        HTTPRequestMethod, "\n",
        CanonicalURI, "\n",
        CanonicalQueryString, "\n",
        CanonicalHeaders, "\n",
        SignedHeaders, "\n",
        HashedRequestPayload
    ]),

    Algorithm = "TC3-HMAC-SHA256",
    Date = utc_date_string(),
    Service = "sts",
    CredentialScope = lists:concat([Date, "/", Service, "/tc3_request"]),
    HashedCanonicalRequest = binary_to_4bit_list(crypto:hash(sha256, CanonicalRequest)),
    StringToSign = lists:concat([
        Algorithm, "\n",
        RequestTimestamp, "\n",
        CredentialScope, "\n",
        HashedCanonicalRequest
    ]),

    SecretKey = Sts#sts.secret_key,
    SecretDate = crypto:mac(hmac, sha256, "TC3" ++ SecretKey, Date),
    SecretService = crypto:mac(hmac, sha256, SecretDate, Service),
    SecretSigning = crypto:mac(hmac, sha256, SecretService, "tc3_request"),
    Signature = binary_to_4bit_list(crypto:mac(hmac, sha256, SecretSigning, StringToSign)),

    SecretId = Sts#sts.secret_id,
    lists:concat([
        Algorithm, " ",
        "Credential=", SecretId, "/", CredentialScope, ", ",
        "SignedHeaders=", SignedHeaders, ", ",
        "Signature=", Signature
    ]).

binary_to_4bit_list(Binary) ->
    string:to_lower(lists:flatten([io_lib:format("~2.16.0b", [N]) || N <- binary_to_list(Binary)])).

utc_date_string() ->
    {{Y, M, D}, _} = calendar:universal_time(),
    RealM = case M < 10 of
                true ->
                    [$0 | integer_to_list(M)];
                false -> M
            end,
    RealD = case D < 10 of
                true ->
                    [$0 | integer_to_list(D)];
                false -> D
            end,
    lists:concat([Y, "-", RealM, "-", RealD]).