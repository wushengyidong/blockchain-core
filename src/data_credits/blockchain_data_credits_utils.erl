%%%-------------------------------------------------------------------
%% @doc
%% == Blockchain DAta Credits Utils ==
%% @end
%%%-------------------------------------------------------------------
-module(blockchain_data_credits_utils).

-export([
    new_payment/6, store_payment/3, encode_payment/1, decode_payment/1, get_payments/3,
    new_payment_req/2, encode_payment_req/1, decode_payment_req/1,
    get_height/2, get_credits/2
]).


-include("blockchain.hrl").
-include("../pb/blockchain_data_credits_pb.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

-define(HEIGHT_KEY, <<"height">>).
-define(CREDITS_KEY, <<"credits">>).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec new_payment(binary(), map(), non_neg_integer(), libp2p_crypto:pubkey_bin(),
                  libp2p_crypto:pubkey_bin(), non_neg_integer()) -> #blockchain_data_credits_payment_pb{}.
new_payment(ID, #{secret := PrivKey, public := PubKey}, Height, Payer, Payee, Amount) -> 
    Payment = #blockchain_data_credits_payment_pb{
        id=ID,
        key=libp2p_crypto:pubkey_to_bin(PubKey),
        height=Height,
        payer=Payer,
        payee=Payee,
        amount=Amount
    },
    EncodedPayment = blockchain_data_credits_pb:encode_msg(Payment),
    SigFun = libp2p_crypto:mk_sig_fun(PrivKey),
    Signature = SigFun(EncodedPayment),
    Payment#blockchain_data_credits_payment_pb{signature=Signature}.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec store_payment(rocksdb:db_handle(), rocksdb:cf_handle(), #blockchain_data_credits_payment_pb{}) -> ok | {error, any()}.
store_payment(DB, CF, #blockchain_data_credits_payment_pb{height=Height, amount=Amount}=Payment) ->
    Encoded = blockchain_data_credits_pb:encode_msg(Payment),
    {ok, Batch} = rocksdb:batch(),
    ok = rocksdb:batch_put(Batch, CF, <<Height>>, Encoded),
    ok = rocksdb:batch_put(Batch, CF, ?HEIGHT_KEY, <<Height>>),
    case Height == 0 of
        true ->
            ok = rocksdb:batch_put(Batch, CF, ?CREDITS_KEY, <<Amount>>);
        false ->
            case rocksdb:get(DB, CF, ?CREDITS_KEY, [{sync, true}]) of
                {ok, <<Credits/integer>>} ->
                    Total = Credits - Amount,
                    ok = rocksdb:batch_put(Batch, CF, ?CREDITS_KEY, <<Total>>);
                _Error ->
                    lager:error("failed to get ~p: ~p", [?CREDITS_KEY, _Error]),
                    _Error
            end
    end,
    ok = rocksdb:write_batch(DB, Batch, []).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec encode_payment(#blockchain_data_credits_payment_pb{}) -> binary().
encode_payment(Payment) ->
    blockchain_data_credits_pb:encode_msg(Payment).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec decode_payment(binary()) -> #blockchain_data_credits_payment_pb{}.
decode_payment(EncodedPayment) ->
    blockchain_data_credits_pb:decode_msg(EncodedPayment, blockchain_data_credits_payment_pb).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec get_payments(rocksdb:db_handle(), rocksdb:cf_handle(), non_neg_integer()) -> [binary()].
get_payments(DB, CF, Height) ->
    get_payments(DB, CF, Height, 0, []).

-spec get_payments(rocksdb:db_handle(), rocksdb:cf_handle(), non_neg_integer(),
                   non_neg_integer(), [binary()]) -> [binary()].
get_payments(_DB, _CF, Height, I, Payments) when Height < I ->
    lists:reverse(Payments);
get_payments(DB, CF, Height, I, Payments) ->
    case rocksdb:get(DB, CF, <<I>>, [{sync, true}]) of
        {ok, Payment} ->
            get_payments(DB, CF, Height, I+1, [Payment|Payments]);
        _Error ->
            lager:error("failed to get ~p: ~p", [<<Height>>, _Error]),
            get_payments(DB, CF, Height, I+1, Payments)
    end.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec new_payment_req(libp2p_crypto:pubkey_bin(), non_neg_integer()) -> #blockchain_data_credits_payment_req_pb{}.
new_payment_req(PubKeyBin, Amount) -> 
    #blockchain_data_credits_payment_req_pb{
        id=crypto:strong_rand_bytes(32),
        payee=PubKeyBin,	
        amount=Amount	
    }.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec encode_payment_req(#blockchain_data_credits_payment_req_pb{}) -> binary().
encode_payment_req(PaymentReq) ->
    blockchain_data_credits_pb:encode_msg(PaymentReq).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec decode_payment_req(binary()) -> #blockchain_data_credits_payment_req_pb{}.
decode_payment_req(EncodedPaymentReq) ->
    blockchain_data_credits_pb:decode_msg(EncodedPaymentReq, blockchain_data_credits_payment_req_pb).

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec get_height(rocksdb:db_handle(), rocksdb:cf_handle()) -> {ok, non_neg_integer()} | {error, any()}.
get_height(DB, CF) ->
    case rocksdb:get(DB, CF, ?HEIGHT_KEY, [{sync, true}]) of
        {ok, <<Height/integer>>} ->
            {ok, Height};
        not_found ->
            {error, not_found};
        _Error ->
            _Error
    end.

%%--------------------------------------------------------------------
%% @doc
%% @end
%%--------------------------------------------------------------------
-spec get_credits(rocksdb:db_handle(), rocksdb:cf_handle()) -> {ok, non_neg_integer()} | {error, any()}.
get_credits(DB, CF) ->
    case rocksdb:get(DB, CF, ?CREDITS_KEY, [{sync, true}]) of
        {ok, <<Credits/integer>>} ->
            {ok, Credits};
        not_found ->
            {error, not_found};
        _Error ->
            _Error
    end.

%% ------------------------------------------------------------------
%% Internal Function Definitions
%% ------------------------------------------------------------------

%% ------------------------------------------------------------------
%% EUNIT Tests
%% ------------------------------------------------------------------
-ifdef(TEST).
-endif.