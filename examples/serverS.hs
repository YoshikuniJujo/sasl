{-# LANGUAGE OverloadedStrings, PackageImports #-}

import "monads-tf" Control.Monad.State
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import Network.Sasl
import Network.Sasl.ScramSha1.Server

import qualified Data.ByteString as BS

data St = St [(BS.ByteString, BS.ByteString)] deriving Show

instance SaslState St where
	getSaslState (St s) = s
	putSaslState s _ = St s

clientFile :: String
clientFile = "examples/scramSha1cl.txt"

main :: IO ()
main = do
	let	slt = "pepper"
		i = 4492
		(stk, svk) = salt "password" slt i
		(_, (_, p)) = sasl $ \"yoshikuni" -> (slt, stk, svk, i)
	r <- runPipe (fromFileLn clientFile =$= p =$= output =$= toHandleLn stdout)
		`runStateT` St [
			("snonce", "7658cddf-0e44-4de2-87df-4132bce97f4"),
			("salt", "pepper"),
			("i", "4492") ]
	print r

output :: Pipe (Either Success BS.ByteString) BS.ByteString (StateT St IO) ()
output = await >>= \mch -> case mch of
	Just (Left (Success Nothing)) -> yield "success"
	Just (Left (Success (Just bs))) -> yield bs
	Just (Right bs) -> yield bs >> output
	_ -> return ()
