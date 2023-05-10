defmodule MyXDR.Nester do
  @moduledoc """
  Automatically generated by xdrgen
  DO NOT EDIT or your changes may be overwritten

  Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

  Representation of Stellar `Nester` type.
  """

  @behaviour XDR.Declaration

  alias MyXDR.{
    NesterNestedEnum,
    NesterNestedStruct,
    NesterNestedUnion
  }

  @struct_spec XDR.Struct.new(
    nested_enum: NesterNestedEnum,
    nested_struct: NesterNestedStruct,
    nested_union: NesterNestedUnion
  )

  @type type_nested_enum :: NesterNestedEnum.t()
  @type type_nested_struct :: NesterNestedStruct.t()
  @type type_nested_union :: NesterNestedUnion.t()

  @type t :: %__MODULE__{nested_enum: type_nested_enum(), nested_struct: type_nested_struct(), nested_union: type_nested_union()}

  defstruct [:nested_enum, :nested_struct, :nested_union]

  @spec new(nested_enum :: type_nested_enum(), nested_struct :: type_nested_struct(), nested_union :: type_nested_union()) :: t()
  def new(
    %NesterNestedEnum{} = nested_enum,
    %NesterNestedStruct{} = nested_struct,
    %NesterNestedUnion{} = nested_union
  ),
  do: %__MODULE__{nested_enum: nested_enum, nested_struct: nested_struct, nested_union: nested_union}

  @impl true
  def encode_xdr(%__MODULE__{nested_enum: nested_enum, nested_struct: nested_struct, nested_union: nested_union}) do
    [nested_enum: nested_enum, nested_struct: nested_struct, nested_union: nested_union]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr()
  end

  @impl true
  def encode_xdr!(%__MODULE__{nested_enum: nested_enum, nested_struct: nested_struct, nested_union: nested_union}) do
    [nested_enum: nested_enum, nested_struct: nested_struct, nested_union: nested_union]
    |> XDR.Struct.new()
    |> XDR.Struct.encode_xdr!()
  end

  @impl true
  def decode_xdr(bytes, struct \\ @struct_spec)

  def decode_xdr(bytes, struct) do
    case XDR.Struct.decode_xdr(bytes, struct) do
      {:ok, {%XDR.Struct{components: [nested_enum: nested_enum, nested_struct: nested_struct, nested_union: nested_union]}, rest}} ->
        {:ok, {new(nested_enum, nested_struct, nested_union), rest}}
      error -> error
    end
  end

  @impl true
  def decode_xdr!(bytes, struct \\ @struct_spec)

  def decode_xdr!(bytes, struct) do
    {%XDR.Struct{components: [nested_enum: nested_enum, nested_struct: nested_struct, nested_union: nested_union]}, rest} =
      XDR.Struct.decode_xdr!(bytes, struct)
    {new(nested_enum, nested_struct, nested_union), rest}
  end
end
