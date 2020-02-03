-module(mp_crypto).
-export([encrypt/2,
         decrypt/2]).

-define(TAGLENGTH, 16).
-define(IV, <<2020020211223344:64>>).
-define(ADD, <<"jflkadsj^de$@#56*sxdfrtg">>).

-spec encrypt(nonempty_string(), binary()) -> binary().
encrypt(Key, Binary) ->
    {B,T} = crypto:crypto_one_time_aead(chacha20_poly1305, Key, ?IV, Binary, ?ADD, ?TAGLENGTH, true),
    erlang:term_to_binary({B,T}).

-spec decrypt(nonempty_string(), binary()) -> {ok, binary()} |
                                               {error, term()}.
decrypt(Key, Binary) ->
    try
        {B, T} = erlang:binary_to_term(Binary),
        RealData = crypto:crypto_one_time_aead(chacha20_poly1305, Key, ?IV, B, ?ADD, T, false),
        {ok, RealData}
    catch
        Error:Reason ->
            {error, {Error, Reason}}
    end.

