{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.Plain.Client (sasl) where

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import Data.Maybe
import Data.Pipe

import qualified Data.ByteString as BS

import Network.Sasl

sasl :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) => (
	BS.ByteString,
	(Bool, Pipe (Either Success BS.ByteString) BS.ByteString m ()) )
sasl = ("PLAIN", client script)

script :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) => Client m
script = Client (Just clientMessage) [] Nothing

clientMessage :: (
	MonadState m, SaslState (StateType m),
	MonadError m, Error (ErrorType m) ) => Send m
clientMessage = do
	st <- gets getSaslState
	let	az = fromMaybe "" $ lookup "authzid" st
		Just ac = lookup "authcid" st
		Just ps = lookup "password" st
	return $ BS.concat [az, "\0", ac, "\0", ps]
