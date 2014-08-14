{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.Plain.Server (sasl) where

import Control.Arrow
import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Pipe

import qualified Data.ByteString as BS

import Network.Sasl

sasl :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) =>
	(BS.ByteString -> BS.ByteString -> m BS.ByteString) -> (
		BS.ByteString,
		(Bool, Pipe BS.ByteString (Either Success BS.ByteString) m ()) )
sasl rt = ("PLAIN", server $ script rt)

readResponse :: BS.ByteString -> (BS.ByteString, BS.ByteString, BS.ByteString)
readResponse rs = (az, ac, ps)
	where
	(az, rst) = second BS.tail $ BS.span (/= 0) rs
	(ac, ps) = second BS.tail $ BS.span (/= 0) rst

script :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) =>
	(BS.ByteString -> BS.ByteString -> m BS.ByteString) -> Server m
script rt =
--	Server (Just $ clientMessage rt) [] (Just $ return "")
	Server (Just $ clientMessage rt) [] Nothing

clientMessage :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) =>
	(BS.ByteString -> BS.ByteString -> m BS.ByteString) -> Receive m
clientMessage rt rs = do
	let (az, ac, ps) = readResponse rs
	ps' <- rt az ac
	unless (ps' == ps) . throwError $ strMsg "not authenticate"
	st <- gets getSaslState
	modify . putSaslState $ ("username", ac) : st
