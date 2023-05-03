module Xdrgen
  module Generators
    class Elixir < Xdrgen::Generators::Base
      MAX_INT = (2**31) - 1

      def generate
        render_definitions(@top)
        render_base_classes
      end

      private
      def render_definitions(node)
        node.definitions.each{|n| render_definition n }
        node.namespaces.each{|n| render_definitions n }
      end

      def render_nested_definitions(defn)
        return unless defn.respond_to? :nested_definitions
        defn.nested_definitions.each{|ndefn| render_definition ndefn}
      end

      def render_definition(defn)
        render_nested_definitions(defn)

        case defn
        when AST::Definitions::Struct ;
          render_struct defn
        when AST::Definitions::Enum ;
          render_enum defn
        when AST::Definitions::Union ;
          render_union defn
        when AST::Definitions::Typedef ;
          render_typedef defn
        when AST::Definitions::Const ;
          render_const defn
        end
      end

      def render_source_comment(out, defn)
        return if defn.is_a?(AST::Definitions::Namespace)

        out.puts <<-EOS.strip_heredoc
          comment ~S"""
          XDR Source Code::\n
        EOS

        out.puts "    " + defn.text_value.split("\n").join("\n    ")

        out.puts <<-EOS.strip_heredoc
          """\n
        EOS
      end

      def render_moduledoc(out, type)
        out.puts <<-EOS.strip_heredoc
          @moduledoc """
          Automatically generated by xdrgen
          DO NOT EDIT or your changes may be overwritten

          Target implementation: elixir_xdr at https://hex.pm/packages/elixir_xdr

          Representation of Stellar `#{type.upcase_first}` type.
          """
        EOS
        out.break
        out.puts "@behaviour XDR.Declaration\n\n"
      end

      def render_define_block(out, module_name)
        out.puts "defmodule #{@namespace}.#{module_name.upcase_first} do"
        out.indent do
          render_moduledoc(out, module_name)
        end
        yield
      ensure
        out.puts "end"
        out.break
      end

      def render_typedef(typedef)
        type = typedef.declaration.type.sub_type
        type_name = type == :optional ? "Optional#{typedef.name.capitalize}"  : typedef.name.downcase

        file_name = "#{type_name.underscore}.ex"
        out = @output.open(file_name)

        render_define_block(out, type_name) do 
          out.indent do
            build_typedef(out, typedef)
          end
        end
        out.close
      end

      def render_const(const)
        file_name = "#{const.name.underscore.downcase}.ex"
        out = @output.open(file_name)

        out.puts "define_type(\"#{const_name const}\", Const, #{const.value});"
      end

      def render_struct(struct)
        file_name = "#{struct.name.underscore.downcase}.ex"
        out = @output.open(file_name)

        render_define_block(out, struct.name) do
          out.indent do
            alias_namespace = "alias #{@namespace}.{"
              struct.members.each_with_index do |m, i|
              alias_namespace += "#{type_reference m, m.name.camelize}#{comma_and_space_unless_last(i, struct.members)}"
              end
            alias_namespace += "} \n\n"
            out.puts alias_namespace

            out.puts "@struct_spec XDR.Struct.new("
            out.indent do
              struct.members.each_with_index do |m, i|
                out.puts "#{m.name.underscore.downcase}: #{type_reference m, m.name.camelize}#{comma_unless_last(i, struct.members)}"
              end
            end
            out.puts ")\n\n"

            struct.members.each_with_index do |m, i|
              out.puts "@type #{m.name.underscore.downcase} :: #{type_reference m, m.name.camelize}.t()"
            end
            out.puts "\n"

            types = "@type t :: %__MODULE__{"
              struct.members.each_with_index do |m, i|
              types += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}()#{comma_and_space_unless_last(i, struct.members)}"
              end
            types += "}\n\n"
            out.puts types

            def_struct = "defstruct ["
              struct.members.each_with_index do |m, i|
              def_struct += ":#{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
              end
            def_struct += "]\n\n"
            out.puts def_struct

            spec = "@spec new("
              struct.members.each_with_index do |m, i|
              spec += "#{m.name.underscore.downcase} :: #{m.name.underscore.downcase}()#{comma_and_space_unless_last(i, struct.members)}"
              end
            spec += ") :: t()\n"
            out.puts spec

            out.puts "def new("
            out.indent do
              struct.members.each_with_index do |m, i|
                out.puts "%#{type_reference m, m.name.camelize}{} = #{m.name.underscore.downcase}#{comma_unless_last(i, struct.members)}"
              end
            end
            out.puts "),\n"
            function = "do: %__MODULE__{"
              struct.members.each_with_index do |m, i|
              function += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
              end
            function += "}\n\n"
            out.puts function

            out.puts "@impl true\n"
            impl = "def encode_xdr(%__MODULE__{"
              struct.members.each_with_index do |m, i|
              impl += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
              end
            impl += "}) do\n"
            out.puts impl
            args = "["
            out.indent do
              struct.members.each_with_index do |m, i|
                args += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
              end
              args += "]\n"
              out.puts args
              out.puts "|> XDR.Struct.new()"
              out.puts "|> XDR.Struct.encode_xdr()"
            end
            out.puts "end\n\n"

            out.puts "@impl true\n"
            impl = "def encode_xdr!(%__MODULE__{"
              struct.members.each_with_index do |m, i|
              impl += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
              end
            impl += "}) do\n"
            out.puts impl
            args = "["
            out.indent do
              struct.members.each_with_index do |m, i|
                args += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
              end
              args += "]\n"
              out.puts args
              out.puts "|> XDR.Struct.new()"
              out.puts "|> XDR.Struct.encode_xdr!()"
            end
            out.puts "end\n\n"

            out.puts "@impl true\n"
            out.puts "def decode_xdr(bytes, struct \\\\ @struct_spec)\n\n"

            out.puts "def decode_xdr(bytes, struct) do"
            out.indent do
              out.puts "case XDR.Struct.decode_xdr(bytes, struct) do"
                out.indent do
                  comp = "{:ok, {%XDR.Struct{components: ["
                    struct.members.each_with_index do |m, i|
                    comp += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
                    end
                  comp += "]}, rest}} ->\n"
                  out.puts comp
                  out.indent do
                    new_comp = "{:ok, {new("
                    struct.members.each_with_index do |m, i|
                      new_comp += "#{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
                    end
                    new_comp += "), rest}}"
                    out.puts new_comp
                  end
                  out.puts "error -> error"
                end
              out.puts "end"
            end
            out.puts "end\n\n"

            out.puts "@impl true\n"
            out.puts "def decode_xdr!(bytes, struct \\\\ @struct_spec)\n\n"

            out.puts "def decode_xdr!(bytes, struct) do"
            out.indent do
              comp = "{%XDR.Struct{components: ["
                struct.members.each_with_index do |m, i|
                comp += "#{m.name.underscore.downcase}: #{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
                end
              comp += "]}, rest} =\n"
              out.puts comp
              out.indent do
                out.puts "XDR.Struct.decode_xdr!(bytes, struct)"
              end
              new_comp = "{new("
                struct.members.each_with_index do |m, i|
                new_comp += "#{m.name.underscore.downcase}#{comma_and_space_unless_last(i, struct.members)}"
                end
              new_comp += "), rest}"
              out.puts new_comp
            end
            out.puts "end"
          end
        end
        out.close
      end

      def render_enum(enum)
        file_name = "#{enum.name.underscore.downcase}.ex"
        out = @output.open(file_name)

        render_define_block(out, enum.name) do 
          out.indent do
            out.puts "@declarations [\n"
            out.indent do
              enum.members.each_with_index do |m, i|
                out.puts "#{m.name}: #{m.value}#{comma_unless_last(i, enum.members)}"
              end
            end
            out.puts "]\n\n"

            out.puts "@enum_spec %XDR.Enum{declarations: @declarations, identifier: nil}\n\n"

            out.puts "@type t :: %__MODULE__{identifier: atom()}\n\n"

            out.puts "defstruct [:identifier]\n\n"

            out.puts "@spec new(type :: atom()) :: t()\n"
            out.puts "def new(type \\\\ :#{enum.members.first.name}), do: %__MODULE__{identifier: type}\n\n"

            out.puts "@impl true"
            out.puts "def encode_xdr(%__MODULE__{identifier: type}) do\n"
            out.indent do
              out.puts "@declarations\n"
              out.puts "|> XDR.Enum.new(type)\n"
              out.puts "|> XDR.Enum.encode_xdr()\n"
            end
            out.puts "end\n\n"

            out.puts "@impl true"
            out.puts "def encode_xdr!(%__MODULE__{identifier: type}) do\n"
            out.indent do
              out.puts "@declarations\n"
              out.puts "|> XDR.Enum.new(type)\n"
              out.puts "|> XDR.Enum.encode_xdr!()\n"
            end
            out.puts "end\n\n"

            out.puts "@impl true"
            out.puts "def decode_xdr(bytes, spec \\\\ @enum_spec)\n\n"

            out.puts "def decode_xdr(bytes, spec) do\n"
            out.indent do
              out.puts "case XDR.Enum.decode_xdr(bytes, spec) do\n"
              out.indent do
                out.puts "{:ok, {%XDR.Enum{identifier: type}, rest}} -> {:ok, {new(type), rest}}\n"
                out.puts "error -> error\n"
              end
              out.puts "end\n"
            end
            out.puts "end\n\n"

            out.puts "@impl true"
            out.puts "def decode_xdr!(bytes, spec \\\\ @enum_spec)\n\n"

            out.puts "def decode_xdr!(bytes, spec) do\n"
            out.indent do
              out.puts "{%XDR.Enum{identifier: type}, rest} = XDR.Enum.decode_xdr!(bytes, spec)\n"
              out.puts "{new(type), rest}\n"
            end
            out.puts "end\n"
          end
        end
      end

      def render_union(union)
        file_name = "#{union.name.underscore.downcase}.ex"
        out = @output.open(file_name)
        union_name_camelize = union.name.camelize
        union_discriminant = union.discriminant

        render_define_block(out, union.name) do 
          out.indent do
            out.puts "alias #{@namespace}.{\n"
            out.indent do
              out.puts "#{type_reference union_discriminant, union_name_camelize},"
              union.arms.each_with_index do |arm, i|
                arm_name = arm.void? ? "Void" : "#{arm.name.camelize}"
                out.puts "#{arm_name}#{comma_unless_last(i, union.arms)}"
              end
            end
            out.puts "}\n\n"

            out.puts "@arms ["
            out.indent do
              union.normal_arms.each_with_index do |arm, i|
                arm_name = arm.void? ? "Void" : "#{type_reference arm.declaration, arm.name.camelize}"

                arm.cases.each do |acase|
                  switch = if acase.value.is_a?(AST::Identifier)
                    "#{member_name(acase.value)}"
                  else
                    acase.value.text_value
                  end

                  out.puts "#{switch}: #{arm_name}#{comma_unless_last(i, union.arms)}"
                end
              end

              if union.default_arm.present?
                out.puts "default: #{type_reference union.default_arm.declaration, union.default_arm.name.camelize}"
              end
            end
            out.puts "]\n\n"

            out.puts "@type value ::"
            out.indent(4) do
              union.arms.each_with_index do |arm, i|
                arm_name = arm.void? ? "Void" : "#{type_reference arm.declaration, arm.name.camelize}"
                if i == 0
                  out.puts "#{arm_name}.t()"
                else
                  out.puts "| #{arm_name}.t()"
                end
              end

              if union.default_arm.present?
                out.puts "| any()"
              end

            end
            out.puts "\n"

            out.puts "@type t :: %__MODULE__{value: value(), type: #{type_reference union_discriminant, union_name_camelize}.t()}\n\n"

            out.puts "defstruct [:value, :type]\n\n"

            out.puts "@spec new(value :: value(), type :: #{type_reference union_discriminant, union_name_camelize}.t()) :: t()\n"
            out.puts "def new(value, %#{type_reference union_discriminant, union_name_camelize}{} = type), do: %__MODULE__{value: value, type: type}\n\n"

            out.puts "@impl true"
            out.puts "def encode_xdr(%__MODULE__{value: value, type: type}) do\n"
            out.indent do
              out.puts "type\n"
              out.puts "|> XDR.Union.new(@arms, value)\n"
              out.puts "|> XDR.Union.encode_xdr()\n"
            end
            out.puts "end\n\n"

            out.puts "@impl true"
            out.puts "def encode_xdr!(%__MODULE__{value: value, type: type}) do\n"
            out.indent do
              out.puts "type\n"
              out.puts "|> XDR.Union.new(@arms, value)\n"
              out.puts "|> XDR.Union.encode_xdr!()\n"
            end
            out.puts "end\n\n"

            out.puts "@impl true"
            out.puts "def decode_xdr(bytes, spec \\\\ union_spec())\n\n"

            out.puts "def decode_xdr(bytes, spec) do\n"
            out.indent do
              out.puts "case XDR.Union.decode_xdr(bytes, spec) do\n"
              out.indent do
                out.puts "{:ok, {{type, value}, rest}} -> {:ok, {new(value, type), rest}}\n"
                out.puts "error -> error\n"
              end
              out.puts "end\n"
            end
            out.puts "end\n\n"

            out.puts "@impl true"
            out.puts "def decode_xdr!(bytes, spec \\\\ union_spec())\n\n"

            out.puts "def decode_xdr!(bytes, spec) do\n"
            out.indent do
              out.puts "{{type, value}, rest} = XDR.Union.decode_xdr!(bytes, spec)\n"
              out.puts "{new(value, type), rest}\n"
            end
            out.puts "end\n\n"

            out.puts "@spec union_spec() :: XDR.Union.t()"
            out.puts "defp union_spec do"
            out.indent do
              out.puts "nil\n"
              out.puts "|> #{type_reference union_discriminant, union_name_camelize}.new()\n"
              out.puts "|> XDR.Union.new(@arms)\n"
            end
            out.puts "end\n"
          end
        end
      end

      private
      def render_base_classes
        file_name = "base.ex"
        out = @output.open(file_name)
        base_py_content = IO.read(__dir__ + "/elixir/base.ex")
        new_base_file = base_py_content.gsub("defmodule ", "defmodule #{@namespace}.")
        out.puts new_base_file
        out.close
      end

      def name(named)
        return nil unless named.respond_to?(:name)

        parent = name named.parent_defn if named.is_a?(AST::Concerns::NestedDefinition)

        # NOTE: classify will strip plurality, so we restore it if necessary
        plural = named.name.underscore.downcase.pluralize == named.name.underscore.downcase
        base   = named.name.underscore.classify
        result = plural ? base.pluralize : base

        "#{parent}#{result}"
      end

      def const_name(named)
        named.name.underscore.upcase
      end

      def member_name(member)
        name(member).underscore.upcase
      end

      def type_reference(decl, container_name)
        type_hint = type_string decl.type

        if type_hint == container_name
          type_hint = "#{type_hint}"
        end

        case decl.type.sub_type
          when :optional
            "Optional#{type_hint}"
          when :var_array, :array
            "#{type_hint}List"
          else
            type_hint
        end
      end

      def comma_unless_last(index, collection)
        if index + 1 >= collection.length
          ""
        else
          ","
        end
      end

      def comma_and_space_unless_last(index, collection)
        if index + 1 >= collection.length
          ""
        else
          ", "
        end
      end

      def type_string(type)
        case type
          when AST::Typespecs::Bool
            "Bool"
          when AST::Typespecs::Double
            "DoubleFloat"
          when AST::Typespecs::Float
            "Float"
          when AST::Typespecs::Hyper
            "HyperInt"
          when AST::Typespecs::Int
            "Int"
          when AST::Typespecs::Opaque
            if type.fixed?
              "FixedOpaque#{type.size}"
            else
              type.size ? "VariableOpaque#{type.size}" : "VariableOpaque"
            end
          when AST::Typespecs::Quadruple
            raise "no quadruple support in elixir"
          when AST::Typespecs::String
            "String#{type.size}"
          when AST::Typespecs::UnsignedHyper
            "HyperUInt"
          when AST::Typespecs::UnsignedInt
            "UInt"
          when AST::Typespecs::Simple
            "#{name type}"
          when AST::Definitions::Base
            "#{name type}"
          when AST::Concerns::NestedDefinition
            "#{name type}"
          else
            raise "Unknown reference type: #{type.class.name}, #{type.class.ancestors}"
        end
      end

      def build_number_typedef(out, number_type, type, attribute)
        out.puts "@type t :: %__MODULE__{#{attribute}: #{number_type}()}\n\n"

        out.puts "defstruct [:#{attribute}]\n\n"

        out.puts "@spec new(value :: #{number_type}()) :: t()\n"
        out.puts "def new(value), do: %__MODULE__{#{attribute}: value}\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr(%__MODULE__{#{attribute}: value}) do\n"
        out.indent do
          out.puts "XDR.#{type}.encode_xdr(%XDR.#{type}{datum: value})\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr!(%__MODULE__{#{attribute}: value}) do\n"
        out.indent do
          out.puts "XDR.#{type}.encode_xdr!(%XDR.#{type}{datum: value})\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr(bytes, term \\\\ nil)\n\n"

        out.puts "def decode_xdr(bytes, _term) do\n"
        out.indent do
          out.puts "case XDR.#{type}.decode_xdr(bytes) do\n"
          out.indent do
            out.puts "{:ok, {%XDR.#{type}{datum: value}, rest}} -> {:ok, {new(value), rest}}\n"
            out.puts "error -> error\n"
          end
          out.puts "end\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr!(bytes, term \\\\ nil)\n\n"

        out.puts "def decode_xdr!(bytes, _term) do\n"
        out.indent do
          out.puts "{%XDR.#{type}{datum: value}, rest} = XDR.#{type}.decode_xdr!(bytes)\n"
          out.puts "{new(value), rest}\n"
        end
        out.puts "end\n"
      end

      def build_bool_typedef(out, number_type, type, attribute)
        out.puts "@type t :: %__MODULE__{#{attribute}: #{number_type}()}\n\n"

        out.puts "defstruct [:#{attribute}]\n\n"

        out.puts "@spec new(value :: #{number_type}()) :: t()\n"
        out.puts "def new(value), do: %__MODULE__{#{attribute}: value}\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr(%__MODULE__{#{attribute}: value}) do\n"
        out.indent do
          out.puts "XDR.#{type}.encode_xdr(%XDR.#{type}{identifier: value})\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr!(%__MODULE__{#{attribute}: value}) do\n"
        out.indent do
          out.puts "XDR.#{type}.encode_xdr!(%XDR.#{type}{identifier: value})\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr(bytes, term \\\\ nil)\n\n"

        out.puts "def decode_xdr(bytes, _term) do\n"
        out.indent do
          out.puts "case XDR.#{type}.decode_xdr(bytes) do\n"
          out.indent do
            out.puts "{:ok, {%XDR.#{type}{identifier: value}, rest}} -> {:ok, {new(value), rest}}\n"
            out.puts "error -> error\n"
          end
          out.puts "end\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr!(bytes, term \\\\ nil)\n\n"

        out.puts "def decode_xdr!(bytes, _term) do\n"
        out.indent do
          out.puts "{%XDR.#{type}{identifier: value}, rest} = XDR.#{type}.decode_xdr!(bytes)\n"
          out.puts "{new(value), rest}\n"
        end
        out.puts "end\n"
      end

      def build_string_typedef(out, typedef, string_type, module_name)
        out.puts "@type t :: %__MODULE__{value: #{string_type}()}\n\n"

        out.puts "defstruct [:value]\n\n"

        unless typedef.declaration.type.size.nil?
          out.puts "@max_lenght #{typedef.declaration.type.size}\n\n"
        end

        out.puts "@spec new(value :: #{string_type}()) :: t()\n"
        out.puts "def new(value), do: %__MODULE__{value: value}\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr(%__MODULE__{value: value}) do\n"
        out.indent do
          out.puts "value\n"
          unless typedef.declaration.type.size.nil?
            out.puts "|> XDR.#{module_name}.new(@max_length)\n"
          else
            out.puts "|> XDR.#{module_name}.new()\n"
          end
          out.puts "|> XDR.#{module_name}.encode_xdr()"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr!(%__MODULE__{value: value}) do\n"
        out.indent do
          out.puts "value\n"
          unless typedef.declaration.type.size.nil?
            out.puts "|> XDR.#{module_name}.new(@max_length)\n"
          else
            out.puts "|> XDR.#{module_name}.new()\n"
          end
          out.puts "|> XDR.#{module_name}.encode_xdr!()"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr(bytes, term \\\\ nil)\n\n"

        out.puts "def decode_xdr(bytes, _term) do\n"
        out.indent do
          out.puts "case XDR.#{module_name}.decode_xdr(bytes) do\n"
          out.indent do
            out.puts "{:ok, {%XDR.#{module_name}{#{module_name.downcase}: value}, rest}} -> {:ok, {new(value), rest}}\n"
            out.puts "error -> error\n"
          end
          out.puts "end\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr!(bytes, term \\\\ nil)\n\n"

        out.puts "def decode_xdr!(bytes, _term) do\n"
        out.indent do
          out.puts "{%XDR.#{module_name}{#{module_name.downcase}: value}, rest} = XDR.#{module_name}.decode_xdr!(bytes)\n"
          out.puts "{new(value), rest}\n"
        end
        out.puts "end\n"
      end

      def build_optional_typedef(out, type, attribute)
        out.puts "alias #{@namespace}.#{type}\n\n"

        out.puts "@optional_spec XDR.Optional.new(#{type})\n\n"

        out.puts "@type #{attribute} :: #{type}.t() | nil\n\n"

        out.puts "@type t :: %__MODULE__{#{attribute}: #{attribute}()}\n\n"

        out.puts "defstruct [:#{attribute}]\n\n"


        out.puts "@spec new(#{attribute} :: #{attribute}()) :: t()\n"
        out.puts "def new(#{attribute} \\\\ nil), do: %__MODULE__{#{attribute}: #{attribute}}\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr(%__MODULE__{#{attribute}: #{attribute}}) do\n"
        out.indent do
          out.puts "#{attribute}"
          out.puts "|> XDR.Optional.new()"
          out.puts "|> XDR.Optional.encode_xdr()"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr!(%__MODULE__{#{attribute}: #{attribute}}) do\n"
        out.indent do
          out.puts "#{attribute}"
          out.puts "|> XDR.Optional.new()"
          out.puts "|> XDR.Optional.encode_xdr!()"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr(bytes, optional_spec \\\\ @optional_spec)\n\n"

        out.puts "def decode_xdr(bytes, optional_spec) do\n"
        out.indent do
          out.puts "case XDR.Optional.decode_xdr(bytes, optional_spec) do\n"
          out.indent do
            out.puts "{:ok, {%XDR.Optional{type: #{attribute}}, rest}} -> {:ok, {new(#{attribute}), rest}}\n"
            out.puts "{:ok, {nil, rest}} -> {:ok, {new(), rest}}"
            out.puts "error -> error\n"
          end
          out.puts "end\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr!(bytes, optional_spec \\\\ @optional_spec)\n\n"

        out.puts "def decode_xdr!(bytes, optional_spec) do\n"
        out.indent do
          out.puts "{%XDR.Optional{identifier: #{attribute}}, rest} = XDR.Optional.decode_xdr!(bytes)\n"
          out.puts "{new(#{attribute}), rest}\n"
          out.puts "{nil, rest} -> {new(), rest}"
        end
        out.puts "end\n"
      end

      def build_opaque_typedef(out_main, type, xdr_module, size = nil)
        name = "#{type}#{size}"

        unless size.nil?
          file_name = "#{type.underscore.downcase}#{size}.ex"
          out = @output.open(file_name)

          render_define_block(out, name) do 
            out.indent do
              out.puts "@type t :: %__MODULE__{opaque: binary()}\n\n"

              out.puts "defstruct [:opaque]\n\n"

              out.puts "@#{type.downcase == "opaque" ? "length" : "max_size"} #{size}\n\n"

              out.puts "@opaque_spec XDR.#{xdr_module}.new(nil, @#{type.downcase == "opaque" ? "length" : "max_size"})\n\n"

              out.puts "@spec new(opaque :: binary()) :: t()\n"
              out.puts "def new(opaque), do: %__MODULE__{opaque: opaque}\n\n"

              out.puts "@impl true"
              out.puts "def encode_xdr(%__MODULE__{opaque: opaque}) do\n"
              out.indent do
                out.puts "XDR.#{xdr_module}.encode_xdr(%XDR.#{xdr_module}{opaque: opaque, #{type.downcase == "opaque" ? "length: @length" : "max_size: @max_size"}})\n"
              end
              out.puts "end\n\n"

              out.puts "@impl true"
              out.puts "def encode_xdr!(%__MODULE__{opaque: opaque}) do\n"
              out.indent do
                out.puts "XDR.#{xdr_module}.encode_xdr!(%XDR.#{xdr_module}{opaque: opaque, #{type.downcase == "opaque" ? "length: @length" : "max_size: @max_size"}})\n"
              end
              out.puts "end\n\n"

              out.puts "@impl true"
              out.puts "def decode_xdr(bytes, spec \\\\ @opaque_spec)\n\n"

              out.puts "def decode_xdr(bytes, spec) do\n"
              out.indent do
                out.puts "case XDR.#{xdr_module}.decode_xdr(bytes, spec) do\n"
                out.indent do
                  out.puts "{:ok, {%XDR.#{xdr_module}{opaque: opaque}, rest}} -> {:ok, {new(opaque), rest}}\n"
                  out.puts "error -> error\n"
                end
                out.puts "end\n"
              end
              out.puts "end\n\n"

              out.puts "@impl true"
              out.puts "def decode_xdr!(bytes, spec \\\\ @opaque_spec)\n\n"

              out.puts "def decode_xdr!(bytes, spec) do\n"
              out.indent do
                out.puts "{%XDR.#{xdr_module}{opaque: opaque}, rest} = XDR.#{xdr_module}.decode_xdr!(bytes)\n"
                out.puts "{new(opaque), rest}\n"
              end
              out.puts "end\n"
            end
          end
        end

        out_main.puts "alias #{@namespace}.#{type}#{size}\n\n"

        out_main.puts "@type t :: %__MODULE__{value: binary()}\n\n"

        out_main.puts "defstruct [:value]\n\n"

        out_main.puts "@spec new(value :: binary()) :: t()\n"
        out_main.puts "def new(value), do: %__MODULE__{value: value}\n\n"

        out_main.puts "@impl true"
        out_main.puts "def encode_xdr(%__MODULE__{value: value}) do\n"
        out_main.indent do
          out_main.puts "value\n"
          out_main.puts "|> #{type}#{size}.new()\n"
          out_main.puts "|> #{type}#{size}.encode_xdr()\n"
        end
        out_main.puts "end\n\n"

        out_main.puts "@impl true"
        out_main.puts "def encode_xdr!(%__MODULE__{opaque: opaque}) do\n"
        out_main.indent do
          out_main.puts "value\n"
          out_main.puts "|> #{type}#{size}.new()\n"
          out_main.puts "|> #{type}#{size}.encode_xdr()\n"
        end
        out_main.puts "end\n\n"

        out_main.puts "@impl true"
        out_main.puts "def decode_xdr(bytes, term \\\\ nil)\n\n"

        out_main.puts "def decode_xdr(bytes, _term) do\n"
        out_main.indent do
          out_main.puts "case XDR.#{type}#{size}.decode_xdr(bytes, term) do\n"
          out_main.indent do
            out_main.puts "{:ok, {%XDR.#{type}#{size}{opaque: value}, rest}} -> {:ok, {new(value), rest}}\n"
            out_main.puts "error -> error\n"
          end
          out_main.puts "end\n"
        end
        out_main.puts "end\n\n"

        out_main.puts "@impl true"
        out_main.puts "def decode_xdr!(bytes, term \\\\ nil)\n\n"

        out_main.puts "def decode_xdr!(bytes, _term) do\n"
        out_main.indent do
          out_main.puts "{%XDR.#{type}#{size}{opaque: value}, rest} = XDR.#{type}#{size}.decode_xdr!(bytes)\n"
          out_main.puts "{new(value), rest}\n"
        end
        out_main.puts "end\n"
      end

      def build_list_typedef(out, base_type, size, list_type)
        out.puts "alias #{@namespace}.#{base_type}\n\n"

        out.puts "@#{list_type.downcase == "fixedarray" ? "length" : "max_length"} #{size.nil? ? "4_294_967_295" : size}\n\n"

        out.puts "@array_type #{base_type}\n\n"

        out.puts "@array_spec %{type: @array_type, #{list_type.downcase == "fixedarray" ? "length: @length" : "max_length: @max_length"}}\n\n"

        out.puts "@type t :: %__MODULE__{items: list(#{base_type}.t())}\n\n"

        out.puts "defstruct [:items]\n\n"

        out.puts "@spec new(items :: list(#{base_type}.t())) :: t()\n"
        out.puts "def new(items), do: %__MODULE__{items: items}\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr(%__MODULE__{items: items}) do\n"
        out.indent do
          out.puts "items\n"
          out.puts "|> XDR.#{list_type}.new(@array_type, @#{list_type.downcase == "fixedarray" ? "length" : "max_length"})\n"
          out.puts "|> XDR.#{list_type}.encode_xdr()\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def encode_xdr!(%__MODULE__{items: items}) do\n"
        out.indent do
          out.puts "items\n"
          out.puts "|> XDR.#{list_type}.new(@array_type, @#{list_type.downcase == "fixedarray" ? "length" : "max_length"})\n"
          out.puts "|> XDR.#{list_type}.encode_xdr!()\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr(bytes, spec \\\\ @array_spec)\n\n"

        out.puts "def decode_xdr(bytes, spec) do\n"
        out.indent do
          out.puts "case XDR.#{list_type}.decode_xdr(bytes, spec) do\n"
          out.indent do
            out.puts "{:ok, {items, rest}} -> {:ok, {new(items), rest}}\n"
            out.puts "error -> error\n"
          end
          out.puts "end\n"
        end
        out.puts "end\n\n"

        out.puts "@impl true"
        out.puts "def decode_xdr!(bytes, spec \\\\ @array_spec)\n\n"

        out.puts "def decode_xdr!(bytes, spec) do\n"
        out.indent do
          out.puts "{items, rest} = XDR.{list_type}.decode_xdr!(bytes, spec)\n"
          out.puts "{new(items), rest}\n"
        end
        out.puts "end\n"
      end

      def build_typedef(out, typedef)
        type = typedef.declaration.type
        base_type = type_string(type)
        name = typedef.name.downcase

        case type.sub_type
          when :optional
            "Optional, #{base_type}"
            build_optional_typedef(out, name.capitalize, name)
          when :array
            is_named, size = type.array_size
            size = is_named ? "\"#{size}\"" : size
            build_list_typedef(out, base_type, size, "FixedArray")
          when :var_array
            is_named, size = type.array_size
            size = is_named ? "\"#{size}\"" : (size || MAX_INT)
            build_list_typedef(out, base_type, size, "VariableArray")
          else
          case type
            when AST::Typespecs::Bool
              build_bool_typedef(out, "boolean", "Bool", "bool")
            when AST::Typespecs::Double
              build_number_typedef(out, "float_number", "DoubleFloat", "float")
            when AST::Typespecs::Float
              build_number_typedef(out, "float_number", "Float", "float")
            when AST::Typespecs::Hyper
              build_number_typedef(out, "integer", "HyperInt", "datum")
            when AST::Typespecs::Int
              build_number_typedef(out, "integer", "Int", "datum")
            when AST::Typespecs::Opaque
              if type.fixed?
                build_opaque_typedef(out, "Opaque", "FixedOpaque", type.size)
              else
                type.size ? build_opaque_typedef(out, "VariableOpaque", "VariableOpaque", type.size) : build_opaque_typedef(out, "VariableOpaque", "VariableOpaque")
              end
            when AST::Typespecs::Quadruple
              raise "no quadruple support in elixir"
            when AST::Typespecs::String
              build_string_typedef(out, typedef, "String.t", "String")
            when AST::Typespecs::UnsignedHyper
              build_number_typedef(out, "non_neg_integer", "HyperUInt", "datum")
            when AST::Typespecs::UnsignedInt
              build_number_typedef(out, "non_neg_integer", "UInt", "datum")
          end
        end
      end
    end
  end
end
