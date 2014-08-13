{-# LANGUAGE OverloadedStrings, PackageImports #-}

import "monads-tf" Control.Monad.State
import Data.Pipe
import Data.Pipe.ByteString
import Network.Sasl
import Network.Sasl.DigestMd5.Server
import System.IO

import qualified Data.ByteString as BS

data St = St [(BS.ByteString, BS.ByteString)] deriving Show

instance SaslState St where
	getSaslState (St s) = s
	putSaslState s _ = St s

clientFile :: String
clientFile = "examples/digestMd5cl.txt"

main :: IO ()
main = do
	let (_, p) = server $ digestMd5Sv (\"yoshikuni" -> "password")
	r <- runPipe (fromFileLn clientFile =$= p =$= output =$= toHandleLn stdout)
		`runStateT` St [
			("realm", "localhost"),
			("nonce", "7658cddf-0e44-4de2-87df-41323bce97f4"),
			("qop", "auth"),
			("charset", "utf-8"),
			("algorithm", "md5-sess") ]
	print r

output :: Pipe (Either Success BS.ByteString) BS.ByteString (StateT St IO) ()
output = await >>= \mch -> case mch of
	Just (Left (Success Nothing)) -> yield "success"
	Just (Right bs) -> yield bs >> output
	_ -> return ()
