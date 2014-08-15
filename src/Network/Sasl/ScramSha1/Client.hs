{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.ScramSha1.Client (
	sasl, saltedPassword, clientKey, serverKey ) where

import Control.Applicative
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Pipe

import Network.Sasl
import Network.Sasl.ScramSha1.ScramSha1

import qualified Data.ByteString.Char8 as BSC

sasl :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) => (
	BSC.ByteString,
	(Bool, Pipe (Either Success BSC.ByteString) BSC.ByteString m ()) )
sasl = ("SCRAM-SHA-1", client scramSha1Client)

scramSha1Client :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) => Client m
scramSha1Client =
	Client (Just clientFirst) [(serverFirst, clientFinal)] (Just serverFinal)

clientFirst :: (MonadState m, SaslState (StateType m)) => Send m
clientFirst = do
	st <- gets getSaslState
	let	Just un = lookup "username" st
		Just nnc = lookup "cnonce" st
		cfmb = clientFirstMessageBare un nnc
	modify . putSaslState $ ("client-first-message-bare", cfmb) : st
	return $ "n,," `BSC.append` cfmb

serverFirst :: (MonadState m, SaslState (StateType m)) => Receive m
serverFirst ch = do
	let Just (nnc, slt, i) = readServerFirstMessage ch
	st <- gets getSaslState
	modify . putSaslState $ [
		("server-first-message", ch),
		("nonce", nnc),
		("salt", slt),
		("i", BSC.pack $ show i) ] ++ st

clientFinal :: (MonadState m, SaslState (StateType m)) => Send m
clientFinal = do
	st <- gets getSaslState
	let	Just ck = case lookup "ClientKey" st of
			Just c -> Just c
			_ -> case lookup "SaltedPassword" st of
				Just sp -> Just $ clientKey sp
				_ -> do	(ps, slt, i) <- psslti st
				{-
				_ -> do	ps <- lookup "password" st
					slt <- lookup "salt" st
					i <- lookup "i" st
					-}
					return . clientKey . saltedPassword ps slt
						. read $ BSC.unpack i
		cb = "n,,"
		Just nonce = lookup "nonce" st
		Just cfmb = lookup "client-first-message-bare" st
		Just sfm = lookup "server-first-message" st
		cfmwop = clientFinalMessageWithoutProof cb nonce
		am = BSC.concat [cfmb, ",", sfm, ",", cfmwop]
	modify . putSaslState $ ("client-final-message-without-proof", cfmwop) : st
	return $ cfmwop `BSC.append` ",p="
		`BSC.append` clientProof ck am
--			(clientKey $ saltedPassword ps slt . read $ BSC.unpack i)
--			am

psslti :: [(BSC.ByteString, BSC.ByteString)] ->
	Maybe (BSC.ByteString, BSC.ByteString, BSC.ByteString)
psslti st = (,,) <$> lookup "password" st <*> lookup "salt" st <*> lookup "i" st

serverFinal :: (
		MonadState m, SaslState (StateType m),
		MonadError m, Error (ErrorType m)
	) => Receive m
serverFinal ch = do
	let Just v = readServerFinalMessage ch
	st <- gets getSaslState
	let	Just sk = case lookup "ServerKey" st of
			Just s -> Just s
			_ -> case lookup "SaltedPassword" st of
				Just sp -> Just $ serverKey sp
				_ -> do	(ps, slt, i) <- psslti st
				{-
				_ -> do	ps <- lookup "password" st
					slt <- lookup "salt" st
					i <- lookup "i" st
					-}
					return . serverKey . saltedPassword ps slt
						. read $ BSC.unpack i
		Just cfmb = lookup "client-first-message-bare" st
		Just sfm = lookup "server-first-message" st
		Just cfmwop = lookup "client-final-message-without-proof" st
		am = BSC.concat [cfmb, ",", sfm, ",", cfmwop]
		sfnm = serverFinalMessage sk
--			(serverKey . saltedPassword ps slt . read $ BSC.unpack i)
			am
	let Just v' = readServerFinalMessage sfnm
	unless (v == v') . throwError $ strMsg "serverFinal: bad"
	modify . putSaslState $ [("verify", v), ("sfm", sfm)] ++ st
