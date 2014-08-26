{-# LANGUAGE OverloadedStrings, TupleSections,
 	FlexibleContexts, TypeSynonymInstances, PackageImports #-}

module Network.Sasl (
	-- * Main
	Client(..), client, Server(..), server, Success(..),
	-- * Types and Classes
	SaslState(..), Send, Receive,
	-- * Error
	SaslError(..), SaslErrorType(..) ) where

import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Maybe
import Data.Pipe

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

class SaslState s where
	initSaslState :: s
	getSaslState :: s -> [(BS.ByteString, BS.ByteString)]
	putSaslState :: [(BS.ByteString, BS.ByteString)] -> s -> s

data Server m = Server (Maybe (Receive m)) [(Send m, Receive m)] (Maybe (Send m))
data Client m = Client (Maybe (Send m)) [(Receive m, Send m)] (Maybe (Receive m))

type Send m = m BS.ByteString
type Receive m = BS.ByteString -> m ()

data Success = Success (Maybe BS.ByteString) deriving Show

data SaslErrorType
	= Aborted
	| AccountDisabled
	| CredentialExpired
	| EncryptionRequired
	| IncorrectEncoding
	| InvalidAuthzid
	| InvalidMechanism
	| MalformedRequest
	| MechanismTooWeak
	| NotAuthorized
	| TemporaryAuthFailure
	| SaslErrorType BS.ByteString
	deriving Show

class Error e => SaslError e where
	fromSaslError :: SaslErrorType -> BS.ByteString -> e

instance SaslError IOError where
	fromSaslError et em = strMsg $ show et ++ ":" ++ BSC.unpack em

server :: Monad m =>
	Server m -> (Bool, Pipe BS.ByteString (Either Success BS.ByteString) m ())
server s@(Server i _ _) = (isJust i, pipeSv_ s)

pipeSv_ :: Monad m =>
	Server m -> Pipe BS.ByteString (Either Success BS.ByteString) m ()
pipeSv_ (Server (Just rcv) srs send') = await >>=
	maybe (return ()) ((>> pipeSv_ (Server Nothing srs send')) . lift . rcv)
pipeSv_ (Server _ [] (Just send')) = lift send' >>= yield . Left . Success . Just
pipeSv_ (Server _ [] _) = yield . Left $ Success Nothing
pipeSv_ (Server _ ((send, rcv) : srs) send') = do
	lift send >>= yield . Right
	await >>= maybe (return ())
		((>> pipeSv_ (Server Nothing srs send')) . lift . rcv)

client :: Monad m => Client m -> (Bool,
	Pipe (Either Success BS.ByteString) BS.ByteString m ())
client c@(Client i _ _) = (isJust i, pipeCl_ c)

voidM :: Monad m => m a -> m ()
voidM = (>> return ())

pipeCl_ :: Monad m =>
	Client m -> Pipe (Either Success BS.ByteString) BS.ByteString m ()
pipeCl_ (Client (Just i) rss rcv') =
	lift i >>= yield >> pipeCl_ (Client Nothing rss rcv')
pipeCl_ (Client _ [] (Just rcv)) = await >>= \mi -> case mi of
	Just (Left (Success (Just d))) -> lift $ rcv d
	Just (Right d) -> lift (rcv d) >> yield "" >> await >>= \mi' -> case mi' of
		Just (Left (Success Nothing)) -> return ()
		_ -> error $ "pipeCl_: " ++ show mi'
	_ -> return ()
pipeCl_ (Client _ [] _) = voidM await
pipeCl_ (Client _ ((rcv, send) : rss) rcv') = await >>= \mbs -> case mbs of
	Just (Right bs) -> lift (rcv bs) >> lift send >>= yield >>
		pipeCl_ (Client Nothing rss rcv')
	_ -> return ()
