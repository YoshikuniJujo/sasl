{-# LANGUAGE OverloadedStrings, PackageImports #-}

import "monads-tf" Control.Monad.State
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import Network.Sasl
import Network.Sasl.DigestMd5.Client

import qualified Data.ByteString as BS

data St = St [(BS.ByteString, BS.ByteString)] deriving Show

instance SaslState St where
	getSaslState (St s) = s
	putSaslState s _ = St s

serverFile :: String
serverFile = "examples/digestMd5sv.txt"

main :: IO ()
main = do
	let (_, (_, p)) = sasl
	r <- runPipe (fromFileLn serverFile =$= input =$= p =$= toHandleLn stdout)
		`runStateT` St [
			("username", "yoshikuni"),
			("password", "password"),
			("cnonce", "00DEADBEEF00"),
			("nc", "00000001"),
			("uri", "xmpp/localhost") ]
	print r

input :: Pipe BS.ByteString (Either Success BS.ByteString) (StateT St IO) ()
input = await >>= \mbs -> case mbs of
	Just "success" -> yield . Left $ Success Nothing
	Just ch -> yield (Right ch) >> input
	_ -> return ()
