defmodule MyXDR.ConstBAR do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `ConstBAR` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.ConstFOO

  @spec const :: integer()
  def const, do: ConstFOO.const
end
