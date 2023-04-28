defmodule MyXDR do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr
  """

  comment ~S"""
  XDR Source Code::

      enum UnionKey {
        ONE = 1,
        TWO = 2,
        OFFER = 3
      };
  """


  comment ~S"""
  XDR Source Code::

      typedef int Foo;
  """

  define_type("Foo", Int)

  comment ~S"""
  XDR Source Code::

      struct {
                  int someInt;
              }
  """


  comment ~S"""
  XDR Source Code::

      struct {
                  int someInt;
                  Foo foo;
              }
  """


  comment ~S"""
  XDR Source Code::

      union MyUnion switch (UnionKey type)
      {
          case ONE:
              struct {
                  int someInt;
              } one;
      
          case TWO:
              struct {
                  int someInt;
                  Foo foo;
              } two;
      
          case OFFER:
              void;
      };
  """


end
