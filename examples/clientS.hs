{-# LANGUAGE OverloadedStrings, PackageImports #-}

import "monads-tf" Control.Monad.State
import Data.Pipe
import Data.Pipe.ByteString
import System.IO
import Network.Sasl
import Network.Sasl.ScramSha1.Client

import qualified Data.ByteString as BS

data St = St [(BS.ByteString, BS.ByteString)] deriving Show

instance SaslState St where
	getSaslState (St s) = s
	putSaslState s _ = St s

serverFile :: String
serverFile = "examples/scramSha1sv.txt"

main :: IO ()
main = do
	let	(_, (_, p)) = sasl
		sp = saltedPassword "password" "pepper" 4492
	r <- runPipe (fromFileLn serverFile =$= input =$= p =$= toHandleLn stdout)
		`runStateT` St [
			("username", "yoshikuni"),
			("password", "password"),
--			("ClientKey", clientKey sp), ("ServerKey", serverKey sp),
--			("SaltedPassword", sp),
			("cnonce", "00DEADBEEF00")
			]
	print r

input :: Pipe BS.ByteString (Either Success BS.ByteString) (StateT St IO) ()
input = await >>= \mbs -> case mbs of
	Just "success" -> yield . Left $ Success Nothing
	Just ch -> yield (Right ch) >> input
	_ -> return ()
