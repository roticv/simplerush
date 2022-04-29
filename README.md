# simplerush

This library depends on libev and ngtcp2. ngtcp2 can be installed by following
instructions on https://github.com/ngtcp2/ngtcp2

## How to build and run tests

```
mkdir build
cmake ../
cmake --build .
ctest
```

## List of bugs/TODO

1. Support connection being closed by server
2. Figure out `MAX_DATA`. Earlier value of 100MB was hit easily
3. Call tryWriteToNgtcp2 after appending data. May require Evloop so that writes happen from the same thread.
4. RushClient/QuicConnection is not thread safe when accessed from multiple threads. Fix that
5. Errors are currently really silent. For example, forgetting to include the extra "/rtmp/" will result in streams continuing, but no live video generated

## Credits

The `flv_to_rush_stream` is based on simpleclient example in ngtcp2.
