# Itsdani Logging

This is a small library that provides a readable console logger intended for
local development usage and a json logger intended for production usage. Both
of these can handle the "extra" parameters, but instead of spreading the extra
parameters in the root of the log object, they are nested under the "extra"
key.
