%%%-------------------------------------------------------------------
%%% @author dasudian
%%% @copyright (C) 2015, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 16. Dec 2015 下午7:51
%%%-------------------------------------------------------------------
-module(cookie).
-author("dasudian").

-define(IM_SECRET, "=jflbkpwfekejade+").

%% @author Barco You <barco@dasudian.com>
%% @copyright 2015 Dasudian
%

-define(AUTH_COOKIE, "_Dasudian_Auth").
%-define(AUTH_SALT, "27ed2d041cdb4b8b2702").
%-define(AUTH_SECRET, "2d0431cd9bda5ba4b98271edcb2e7102").
%-define(AUTH_EXPIRY_DAYS, 7).
%-define(ENC_IV, <<207,94,217,158,198,63,132,205,35,187,246,2,56,122,250,33>>).
%-define(ENC_KEY,
%		<<110,56,121,28,235,159,77,154,160,5,130,210,204,32,26,224,255,86,101,71,61,3,
%		  66,69,30,39,42,0,116,93,204,99>>).

-define(AUTH_SALT, "27ed29a41cde4b8b2c02").
-define(AUTH_SECRET, "2d0231cd9bda5babb9a251ed6b2e7802").
-define(AUTH_EXPIRY_DAYS, 7).
-define(ENC_IV, <<207,94,217,158,189,63,132,205,35,126,236,2,56,125,230,33>>).
-define(ENC_KEY,
	<<110,56,121,128,35,59,77,154,164,5,130,220,204,32,206,224,252,86,101,71,61,23,
	66,69,30,39,42,10,116,93,204,99>>).


%% --------------------------------------------------------------------------------------
%% API Function Exports
%% --------------------------------------------------------------------------------------

-export([generate_token/5, verify_token/1]).
-export([generate_token/3]).
-export([generate_token1/1, get_user_id/1, generate_token2/1, generate_token3/1, generate_token4/1]).
-export([generate_username/1]).
-export([generate_client_id/1]).
%% --------------------------------------------------------------------------------------
%% API Function Definitions
%% --------------------------------------------------------------------------------------
generate_token1({Pid, DynData}) ->
	io:format("token1=====~p~n",[ok]),
	AppId = "1635_A_93fHW6VMmE0wzjUSzA",
	UserId = hash_to_string(crypto:strong_rand_bytes(8)),
	ClientId = hash_to_string(crypto:strong_rand_bytes(8)),
	generate_token(AppId, UserId, ClientId).

generate_token2({Pid, DynData}) ->
	io:format("token2=====~p~n",[ok]),
	AppId = "1636_A_93u78FTtfPZbiJBjLU",
	UserId = hash_to_string(crypto:strong_rand_bytes(8)),
	ClientId = hash_to_string(crypto:strong_rand_bytes(8)),
	generate_token(AppId, UserId, ClientId).

generate_token3({Pid, DynData}) ->
	AppId = "1636_A_93u6zDOC4kGkcSDGi0",
	UserId = hash_to_string(crypto:strong_rand_bytes(8)),
	ClientId = hash_to_string(crypto:strong_rand_bytes(8)),
	generate_token(AppId, UserId, ClientId).

generate_token4({Pid, DynData}) ->
	AppId = "139_A_92QZPza2Rn37mfzrU0",
	UserId = hash_to_string(crypto:strong_rand_bytes(8)),
	ClientId = hash_to_string(crypto:strong_rand_bytes(8)),
	generate_token(AppId, UserId, ClientId).

generate_username({Pid, DynData}) ->
	io:format("username========ok~n"),
	hash_to_string(crypto:strong_rand_bytes(8)).

generate_client_id({Pid, DynData}) ->
	io:format("===~p~n",[ok]),
       	A = "1635_A_" ++ hash_to_string(crypto:strong_rand_bytes(8)),
	io:format("~p~n", [A]).

get_user_id(Token) ->
	{ok, {_Id, UserId, _ClientId, _R, _S}} = decode_token(Token),
	UserId.

generate_token(AppId, UserId, ClientId) ->
	Random = float_to_list(random:uniform()),
	generate_token(AppId, UserId, ClientId, Random, ?IM_SECRET).

generate_token(AppId, UserId, ClientId, Random, TokenSecret) ->
	encode_token(AppId, UserId, ClientId, Random, TokenSecret).

% {ok, {AppId, UserId, ExpiryDate, TokenScret}}
verify_token(Token) ->
	decode_token(Token).

hash_to_string(HashBin) when is_binary(HashBin) ->
	lists:flatten(lists:map(
		fun(X) -> io_lib:format("~2.16.0b", [X]) end,
		binary_to_list(HashBin))).

%% --------------------------------------------------------------------------------------
%% Private Function Definitions
%% --------------------------------------------------------------------------------------


decode_token(Token) ->
	{Expire, SecretInfo} = binary_to_term(base64:decode(Token)),
	case Expire >= calendar:local_time() of
		true ->
			{Id1, Id2, ClientId, Random, TokenSecret} = decrypt(SecretInfo),
			{ok, {Id1, Id2, ClientId, Random, TokenSecret}};
		false ->
			{error, expired}
	end.

encode_token(Id1, Id2, ClientId, Random, TokenSecret) ->
	SecretInfo = encrypt({Id1, Id2, ClientId, Random, TokenSecret}),
	TokenValue = {get_expiry(), SecretInfo},
	binary_to_list(base64:encode(term_to_binary(TokenValue))).

get_expiry() ->
	{Date, Time} = calendar:local_time(),
	NewDate = calendar:gregorian_days_to_date(calendar:date_to_gregorian_days(Date) + ?AUTH_EXPIRY_DAYS),
	{NewDate, Time}.

encrypt(Value) ->
	State = crypto:stream_init(aes_ctr, ?ENC_KEY, ?ENC_IV),
	{_NewState, V} = crypto:stream_encrypt(State, term_to_binary([Value, ?AUTH_SALT])),
	V.

decrypt(Value) ->
	State = crypto:stream_init(aes_ctr, ?ENC_KEY, ?ENC_IV),
	{_NewState, VV} = crypto:stream_decrypt(State, Value),
	[V, ?AUTH_SALT] = binary_to_term(VV),
	V.

