#!/usr/bin/env bash

GIT_REPO="https://github.com/idrissneumann/falcosidekick"
GIT_BRANCH="feat_add_quickwit_output"

[[ ! -d falco_src ]] && git clone "${GIT_REPO}" falco_src

cd falco_src
git checkout "${GIT_BRANCH}"
git add .
git stash
git stash clear
git pull --rebase
cd -

docker-compose up --build --force-recreate
