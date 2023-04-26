defmodule MyXDR.nestedEnum do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `nestedEnum` type.
  """

  @behaviour XDR.Declaration

  @declarations [
    BLAH_1: 0,
    BLAH_2: 1
  ]

  @enum_spec %XDR.Enum{declarations: @declarations, indentifier: nil}

  @type t :: %__MODULE__{identifier: atom()}

  defstruct [:identifier]

  @spec new(type :: atom()) :: t()
  def new(type \\ :BLAH_1), do: %__MODULE__{identifier: type}

  @impl true
  def encode_xdr(%__MODULE__{identifier: type}), do:
    @declarations
    |> XDR.Enum.new(type)
    |> XDR.Enum.encode_xdr()

  @impl true
  def encode_xdr!(%__MODULE__{identifier: type}), do:
    @declarations
    |> XDR.Enum.new(type)
    |> XDR.Enum.encode_xdr!()

  @impl true
  def decode_xdr(bytes, spec \\ @enum_spec)

  def decode_xdr(bytes, spec) do:
    case XDR.Enum.decode_xdr(bytes, spec) do
      {:ok, {%XDR.Enum{identifier: type}, rest}} -> {:ok, {new(type), rest}}
      error -> error
    end

  @impl true
  def decode_xdr!(bytes, spec \\ @enum_spec)

  def decode_xdr!(bytes, spec) do
    {%XDR.Enum{identifier: type}, rest} = XDR.Enum.decode_xdr!(bytes, spec)
    {new(type), rest}
  end
end
