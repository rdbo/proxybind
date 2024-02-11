#!/bin/sh

while :; do
	printf "pong" | nc -l -p 1337
	printf "\n"
done
