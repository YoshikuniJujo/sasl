{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import Data.Pipe
import Data.Pipe.ByteString
import Network.Sasl
import Network.Sasl.External.Server
import System.IO

import qualified Data.ByteString as BS

data St = St [(BS.ByteString, BS.ByteString)] deriving Show

instance SaslState St where
	getSaslState (St s) = s
	putSaslState s _ = St s

clientFile :: String
clientFile = "examples/externalCl.txt"

main :: IO ()
main = do
	let (_, (_, p)) = sasl check
	r <- runPipe (fromFileLn clientFile =$= p =$= output =$= toHandleLn stdout)
		`runStateT` St []
	print r

check :: (MonadError m, SaslError (ErrorType m)) =>
	BS.ByteString -> m ()
check "yoshikuni" = return ()
check _ = throwError $ fromSaslError NotAuthorized "incorrct username"

output :: Pipe (Either Success BS.ByteString) BS.ByteString (StateT St IO) ()
output = await >>= \mch -> case mch of
	Just (Left (Success Nothing)) -> yield "success"
	Just (Right bs) -> yield bs >> output
	_ -> return ()
