# frozen_string_literal: true

module Legion
  module Crypt
    module Helper
      def vault_namespace
        @vault_namespace ||= derive_vault_namespace
      end

      def vault_get(path = nil)
        Legion::Crypt.get(vault_path(path))
      end

      def vault_write(path, **data)
        Legion::Crypt.write(vault_path(path), **data)
      end

      def vault_exist?(path = nil)
        Legion::Crypt.exist?(vault_path(path))
      end

      private

      def vault_path(suffix = nil)
        base = vault_namespace
        suffix ? "#{base}/#{suffix}" : base
      end

      def derive_vault_namespace
        if respond_to?(:lex_filename)
          fname = lex_filename
          fname.is_a?(Array) ? fname.first : fname
        else
          derive_vault_namespace_from_class
        end
      end

      def derive_vault_namespace_from_class
        name = respond_to?(:ancestors) ? ancestors.first.to_s : self.class.to_s
        parts = name.split('::')
        ext_idx = parts.index('Extensions')
        target = if ext_idx && parts[ext_idx + 1]
                   parts[ext_idx + 1]
                 else
                   parts.last
                 end
        target.gsub(/([A-Z]+)([A-Z][a-z])/, '\1_\2')
              .gsub(/([a-z\d])([A-Z])/, '\1_\2')
              .downcase
      end
    end
  end
end
