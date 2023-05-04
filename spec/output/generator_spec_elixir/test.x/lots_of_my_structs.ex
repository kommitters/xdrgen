defmodule MyXDR.LotsOfMyStructs do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `LotsOfMyStructs` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.{ 
    MyStructList
  } 

  @struct_spec XDR.Struct.new(
    members: MyStructList
  )

  @type members :: MyStructList.t()

  @type t :: %__MODULE__{members: members()}

  defstruct [:members]

  @spec new(members :: members()) :: t()
  def new(
    %MyStructList{} = members
  ),
  do: %__MODULE__{members: members}

  @impl true
  def encode_xdr(%__MODULE__{members: members}) do
    [members: members]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{members: members}) do
    [members: members]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, struct \\ @struct_spec)

  def decode_xdr(bytes, struct) do
    case XDR.Struct.decode_xdr(bytes, struct) do
      {:ok, {%XDR.Struct{components: [members: members]}, rest}} ->
        {:ok, {new(members), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, struct \\ @struct_spec)

  def decode_xdr!(bytes, struct) do
    {%XDR.Struct{components: [members: members]}, rest} =
      XDR.Struct.decode_xdr!(bytes, struct)
    {new(members), rest}
  end
end
