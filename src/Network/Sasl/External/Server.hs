{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.External.Server (sasl) where

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Pipe

import qualified Data.ByteString as BS

import Network.Sasl

sasl :: (
	MonadState m, SaslState (StateType m),
	MonadError m, SaslError (ErrorType m) ) =>
	(BS.ByteString -> m Bool) -> (
		BS.ByteString,
		(Bool, Pipe BS.ByteString (Either Success BS.ByteString) m ()) )
sasl rt = ("EXTERNAL", server $ script rt)

script :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) =>
	(BS.ByteString -> m Bool) -> Server m
script rt = Server (Just $ clientMessage rt) [] Nothing

clientMessage :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) =>
	(BS.ByteString -> m Bool) -> Receive m
clientMessage rt rs = do
	ok <- rt rs
	unless ok . throwError $ strMsg "not authenticate"
	st <- gets getSaslState
	modify . putSaslState $ ("username", rs) : st
