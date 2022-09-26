defmodule MyXDR do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: exdr at https://hex.pm/packages/exdr
  """

  use XDR.Base

  comment ~S"""
  === xdr source ============================================================

      typedef hyper int64;

  ===========================================================================
  """
  define_type("Int64", HyperInt)

  comment ~S"""
  === xdr source ============================================================

      struct MyStruct
      {
          int    someInt;
          int64  aBigInt;
          opaque someOpaque[10];
          string someString<>;
          string maxString<100>;
      };

  ===========================================================================
  """
  define_type("MyStruct", Struct,
    some_int: build_type(Int),
    a_big_int: "Int64",
    some_opaque: build_type(Opaque, 10),
    some_string: build_type(XDR.Type.String, ),
    max_string: build_type(XDR.Type.String, 100)
  )

end