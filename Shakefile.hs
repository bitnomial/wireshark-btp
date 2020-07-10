#!/usr/bin/env stack
{- stack
  --resolver lts-12.5
  runghc
  --package shake
-}

module Main where

import           Control.Monad              (when)
import           Data.Bool                  (bool)
import           Development.Shake          (Action, CmdOption (RemEnv), cmd_, doesDirectoryExist, need, phony,
                                             removeFilesAfter, shakeArgs, shakeOptions, want, (%>))
import           Development.Shake.FilePath ((<.>), (</>))
import           System.Info                (os)


main :: IO ()
main = shakeArgs shakeOptions $ do
    want [sharedObject]

    wiresharkCMake %> \_ -> do
        cmd_ "mkdir -p" buildPath
        cmd_ "wget -q" ["-O", wiresharkTarPath, wiresharkUrl]
        cmd_ "tar -xJ" ["-f", wiresharkTarPath, "-C", buildPath]

    sharedObject %> \_ -> do
        need [wiresharkCMake]
        cmd_ "mkdir -p" pluginPath
        cmd_ "cp" [cmakeLists, pluginPath]
        cmd_ "cp" [packetBtp, pluginPath]
        cmd_ (RemEnv "PYTHONPATH")
            "cmake -DCUSTOM_PLUGIN_SRC_DIR=plugins/epan/btp"
            ["-S", wiresharkSrc, "-B", wiresharkBuild]
        cmd_ (RemEnv "PYTHONPATH") "make" ["-C", wiresharkBuild]
        cmd_ "cp" [btpObject, sharedObject]

    phony "install" $ do
        need [sharedObject]
        mapM_ installAtPath installPaths

    phony "clean" $ removeFilesAfter buildPath ["//"]


major :: FilePath
major = "3"


minor :: FilePath
minor = "0"


maintenance :: FilePath
maintenance = "2"


version :: FilePath
version = major <.> minor <.> maintenance


buildPath :: FilePath
buildPath = ".build"


python :: FilePath
python = buildPath </> "python"


pythonPath :: FilePath
pythonPath = python </> "bin"


wiresharkBuild :: FilePath
wiresharkBuild = buildPath </> "build"


wireshark :: FilePath
wireshark = "wireshark-" <> version


installPaths :: [FilePath]
installPaths = [libPath, appPath]
  where
    libPath = "/usr/local/lib/wireshark/plugins" </> major <> "-" <> minor </> "epan/"
    appPath = "/Applications/Wireshark.app/Contents/PlugIns/wireshark" </> major <> "-" <> minor </> "epan/"


installAtPath :: FilePath -> Action ()
installAtPath fp = doesDirectoryExist fp >>= (`when` cmd_ "cp" sharedObject fp)


pluginPath :: FilePath
pluginPath = wiresharkSrc </> "plugins/epan/btp/"


wiresharkSrc :: FilePath
wiresharkSrc = buildPath </> wireshark


wiresharkCMake :: FilePath
wiresharkCMake = wiresharkSrc </> "CMakeLists" <.> "txt"


wiresharkTar :: FilePath
wiresharkTar = wireshark <.> "tar.xz"


wiresharkTarPath :: FilePath
wiresharkTarPath = buildPath </> wiresharkTar


wiresharkUrl :: FilePath
wiresharkUrl = "https://2.na.dl.wireshark.org/src/all-versions" </> wiresharkTar


osIsDarwin :: Bool
osIsDarwin = os == "darwin"


btpObject :: FilePath
btpObject = wiresharkBuild </> "run" </> path </> "epan/btp.so"
  where
    path      = bool linuxPath macPath osIsDarwin
    macPath   = "Wireshark.app/Contents/PlugIns/wireshark/" </> major <> "-" <> minor
    linuxPath = "plugins" </> major <.> minor

sharedObject :: FilePath
sharedObject = buildPath </> "dist/x86_64-" <> osName </> "btp.so"
  where
    osName = bool os "osx" osIsDarwin


cmakeLists :: FilePath
cmakeLists = "CMakeLists" <.> "txt"


packetBtp :: FilePath
packetBtp = "packet-btp" <.> "c"
