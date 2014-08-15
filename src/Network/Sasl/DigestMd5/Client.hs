{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.DigestMd5.Client (sasl) where

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import Data.Pipe

import Network.Sasl
import Network.Sasl.DigestMd5.DigestMd5
import Network.Sasl.DigestMd5.Papillon

import qualified Data.ByteString as BS

sasl :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) => (
	BS.ByteString,
	(Bool, Pipe (Either Success BS.ByteString) BS.ByteString m ()) )
sasl = ("DIGEST-MD5", client digestMd5Cl)


digestMd5Cl :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) => Client m
digestMd5Cl = Client Nothing (zip svs cls) (Just . const $ return ()) -- Nothing

cls :: (MonadState m, SaslState (StateType m)) => [Send m]
-- client = [mkResponse, return ""]
cls = [mkResponse]

svs :: (MonadState m, SaslState (StateType m)) => [Receive m]
svs = [putReceive]

mkResponse :: (MonadState m, SaslState (StateType m)) => Send m
mkResponse = do
	st <- gets getSaslState
	let	Just ps = lookup "password" st
		Just rlm = lookup "realm" st
		Just n = lookup "nonce" st
		Just q = lookup "qop" st
		Just c = lookup "charset" st
		Just un = lookup "username" st
		Just uri = lookup "uri" st
		Just cn = lookup "cnonce" st
		Just nc = lookup "nc" st
	modify . putSaslState $ [
		("username", un),
		("digest-uri", uri),
		("nc", nc),
		("cnonce", cn) ] ++ st
	return . fromDigestResponse $ DR {
		drUserName = un,
		drRealm = rlm,
		drPassword = ps,
		drCnonce = cn,
		drNonce = n,
		drNc = nc,
		drQop = q,
		drDigestUri = uri,
		drCharset = c }

putReceive :: (MonadState m, SaslState (StateType m)) => Receive m
putReceive bs = do
	let Just ch = parseAtts bs
	st <- gets getSaslState
	let	Just rlm = lookup "realm" ch
		Just n = lookup "nonce" ch
		Just q = lookup "qop" ch
		Just c = lookup "charset" ch
		Just a = lookup "algorithm" ch
	modify . putSaslState $ [
		("realm", rlm),
		("nonce", n),
		("qop", q),
		("charset", c),
		("algorithm", a) ] ++ st
