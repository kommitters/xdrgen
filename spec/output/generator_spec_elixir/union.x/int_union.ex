defmodule MyXDR.IntUnion do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `IntUnion` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.{
    build_type(Int),
    Error,
    build_type(MultiList)
  }

  @arms [
    0: Error,
    1: build_type(MultiList)
  ]

  @type value ::
          Error.t()
          | build_type(MultiList).t()

  @type t :: %__MODULE__{value: value(), type: build_type(Int).t()}

  defstruct [:value, :type]

  @spec new(value :: value(), type :: build_type(Int).t()) :: t()
  def new(value, %build_type(Int){} = type), do: %__MODULE__{value: value, type: type}

  @impl true
  def encode_xdr(%__MODULE__{value: value, type: type}) do
    type
    |> XDR.Union.new(@arms, value)
    |> XDR.Union.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{value: value, type: type}) do
    type
    |> XDR.Union.new(@arms, value)
    |> XDR.Union.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, spec \\ union_spec())

  def decode_xdr(bytes, spec) do
    case XDR.Union.decode_xdr(bytes, spec) do
      {:ok, {{type, value}, rest}} -> {:ok, {new(value, type), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, spec \\ union_spec())

  def decode_xdr!(bytes, spec) do
    {{type, value}, rest} = XDR.Union.decode_xdr!(bytes, spec)
    {new(value, type), rest}
  end

  @spec union_spec() :: XDR.Union.t()
  defp union_spec do
    nil
    |> build_type(Int).new()
    |> XDR.Union.new(@arms)
  end
end
