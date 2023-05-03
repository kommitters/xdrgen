defmodule MyXDR do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr
  """

  comment ~S"""
  XDR Source Code::

      const FOO = 1;
  """

  define_type("FOO", Const, 1);

  comment ~S"""
  XDR Source Code::

      typedef int TestArray[FOO];
  """


  comment ~S"""
  XDR Source Code::

      typedef int TestArray2<FOO>;
  """


end