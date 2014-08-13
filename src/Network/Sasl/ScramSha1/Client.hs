{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.ScramSha1.Client (Client(..), scramSha1Client) where

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error

import Network.Sasl
import Network.Sasl.ScramSha1.ScramSha1

import qualified Data.ByteString.Char8 as BSC

scramSha1Client :: (MonadState m, SaslState (StateType m), MonadError m) => Client m
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
	let	Just ps = lookup "password" st
		Just slt = lookup "salt" st
		Just i = lookup "i" st
		cb = "n,,"
		Just nonce = lookup "nonce" st
		Just cfmb = lookup "client-first-message-bare" st
		Just sfm = lookup "server-first-message" st
		cfmwop = clientFinalMessageWithoutProof cb nonce
		am = BSC.concat [cfmb, ",", sfm, ",", cfmwop]
	return $ cfmwop `BSC.append` ",p="
		`BSC.append` clientProof am ps slt (read $ BSC.unpack i)

serverFinal :: (MonadState m, SaslState (StateType m)) => Receive m
serverFinal ch = do
	let Just v = readServerFinalMessage ch
	st <- gets getSaslState
	let	Just un = lookup "username" st
		Just ps = lookup "password" st
		Just slt = lookup "salt" st
		Just i = lookup "i" st
		cb = "n,,"
		Just cnnc = lookup "cnonce" st
		Just nnc = lookup "nonce" st
		sfm = serverFinalMessage un ps slt (read $ BSC.unpack i) cb cnnc nnc
	let Just v' = readServerFinalMessage sfm
	unless (v == v') $ error "serverFinal: bad"
	modify . putSaslState $ [("verify", v), ("sfm", sfm)] ++ st
