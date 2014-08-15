{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import Data.Pipe
import Data.Pipe.ByteString
import Network.Sasl
import Network.Sasl.Plain.Server
import System.IO

import qualified Data.ByteString as BS

data St = St [(BS.ByteString, BS.ByteString)] deriving Show

instance SaslState St where
	getSaslState (St s) = s
	putSaslState s _ = St s

clientFile :: String
clientFile = "examples/plainCl.txt"

main :: IO ()
main = do
	let (_, (_, p)) = sasl check
	r <- runPipe (fromFileLn clientFile =$= p =$= output =$= toHandleLn stdout)
		`runStateT` St []
	print r

check :: (Monad m, MonadError m, SaslError (ErrorType m)) =>
	BS.ByteString -> BS.ByteString -> BS.ByteString -> m ()
check "" "yoshikuni" "password" = return ()
check _ _ _ = throwError $
	fromSaslError NotAuthorized "incorrect username or password"

output :: Pipe (Either Success BS.ByteString) BS.ByteString (StateT St IO) ()
output = await >>= \mch -> case mch of
	Just (Left (Success Nothing)) -> yield "success"
	Just (Right bs) -> yield bs >> output
	_ -> return ()
