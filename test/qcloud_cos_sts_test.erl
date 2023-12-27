%%%-------------------------------------------------------------------
%% @author lesliechou lesliechou7@outlook.com
%% @doc
%% Sts test interface module.
%% @end
%%%-------------------------------------------------------------------
-module(qcloud_cos_sts_test).
-author("lesliechou").

-include_lib("eunit/include/eunit.hrl").
-ifdef(TEST).

init_test() ->
    Config = #{
        secret_id => "TEST123456789TEST",
        secret_key => "TEST123456789TEST",
        bucket => "test-123456789",
        region => "ap-guangzhou",
        resource_prefix => "/test/*",
        allow_actions => [
            "name/cos:PutObject",
            "name/cos:GetObject"
        ]
    },
    ?_assertEqual(
        cos_sts:init(Config),
        {
            sts,
            "TEST123456789TEST",
            "TEST123456789TEST",
            1800,
            "test-123456789",
            "ap-guangzhou",
            "qcs::cos:ap-guangzhou:uid/123456789:test-123456789/test/*",
            [
                "name/cos:PutObject","name/cos:GetObject"
            ],
            [],
            [],
            "https://sts.tencentcloudapi.com/",
            "sts.tencentcloudapi.com"
        }
    ).

-endif.