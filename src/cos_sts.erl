%%%-------------------------------------------------------------------
%%% @author lesliechou
%%% @doc
%%% Qcloud cos sts interface.
%%% @end
%%% Created : 26. 11月 2021 0:01
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

%% @doc Init sts config.
-spec init(Config :: map()) -> {ok, Sts :: #sts{}} | {error, Reason :: term()}.
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
        _ ->
            {ok, Sts}
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
        {ok, Sts#sts{resource = Resource}}
    catch
        _ : _ ->
            {error, {invalid_value, bucket}}
    end.

%% @doc Request for credential.
-spec get_credential(#sts{}) -> map() | {error, Reason :: term()}.
get_credential(Sts) ->
    Policy = case Sts#sts.policy of
                 "" ->
                     [
                         {<<"version">>, "2.0"},
                         {<<"statement">>, [
                             [
                                 {<<"action">>, Sts#sts.allow_actions},
                                 {<<"effect">>, "allow"},
                                 {<<"resource">>, Sts#sts.resource}
                             ]
                         ]}
                     ];
                 _ ->
                     Sts#sts.policy
             end,
    PolicyEncode = http_uri:encode(jsx:encode(Policy)),

    Data = [
        {<<"SecretId">>, Sts#sts.secret_id},
        {<<"Timestamp">>, timestamp()},
        {<<"Nonce">>, random_number(100000, 200000)},
        {<<"Action">>, "GetFederationToken"},
        {<<"Version">>, "2018-08-13"},
        {<<"DurationSeconds">>, Sts#sts.duration_seconds},
        {<<"Name">>, "cos-sts-erlang"},
        {<<"Policy">>, PolicyEncode},
        {<<"Region">>, Sts#sts.region}
    ],
    Sign = encrypt(Sts, "POST", Sts#sts.domain, Data),

    Method = post,
    Url = Sts#sts.url,
    Headers = [],
    ContentType = "application/x-www-form-urlencoded",
    Body = list_to_binary(flat_params([{<<"Signature">>, Sign} | Data])),
    HttpOpts = [{timeout, 5000}],
    Opts = [],
    case httpc:request(Method, {Url, Headers, ContentType, Body}, HttpOpts, Opts) of
        {ok, Result} ->
            case jsx:decode(Result) of
                ResultMap when is_map(ResultMap) ->
                    parse_response(ResultMap);
                _ ->
                    {error, {json_decode_fail}}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

timestamp() ->
    {M, S, _} = os:timestamp(),
    M * 1000000 + S.

random_number(Min, Max) when is_integer(Min), is_integer(Max), Min < Max ->
    rand:seed(os:timestamp()),
    Min + rand:uniform(Max - Min).

encrypt(Sts, Method, Domain, KV) ->
    KVString = flat_params(KV),
    Source = lists:concat([Method, Domain, "/?", KVString]),
    Sign = crypto:mac(hmac, sha,
        unicode:characters_to_binary(Sts#sts.secret_key),
        unicode:characters_to_binary(Source)
    ),
    string:strip(base64:encode_to_string(Sign), right).

flat_params(KV) ->
    flat_params(lists:reverse(KV), []).
flat_params([{Key, Value} | T], KVStringList) ->
    flat_params(T, [lists:concat([binary_to_list(Key), "=", Value]) | KVStringList]);
flat_params([], KVStringList) ->
    string:join(KVStringList, "&").

parse_response(Map) ->
    maps:fold(
        fun(Key, Value, AccMap) ->
            case is_map(Value) of
                true ->
                    AccMap#{binary_to_atom(Key, utf8) => parse_response(Value)};
                false ->
                    AccMap#{binary_to_atom(Key, utf8) => Value}
            end
        end, #{}, Map).