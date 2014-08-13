{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.DigestMd5.Client (SaslState(..), client, digestMd5Cl) where

import "monads-tf" Control.Monad.State

import Network.Sasl
import Network.Sasl.DigestMd5.DigestMd5
import Network.Sasl.DigestMd5.Papillon

digestMd5Cl :: (MonadState m, SaslState (StateType m)) => Client m
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
	modify $ putSaslState $ [
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
	modify $ putSaslState $ [
		("realm", rlm),
		("nonce", n),
		("qop", q),
		("charset", c),
		("algorithm", a) ] ++ st
