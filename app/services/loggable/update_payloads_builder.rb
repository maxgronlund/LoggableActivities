module Loggable
  module UpdatePayloadsBuilder
    

    def build_update_payloads()
      @update_payloads = []

      previous_values, current_values = primary_update_attrs
      build_primary_update_payload(previous_values, current_values)

      self.class.relations.each do |relation_config|
        build_update_relation_payloads(relation_config)
      end
      @update_payloads
      
    end


    def primary_update_attrs
      previous_values = saved_changes.transform_values(&:first)
      current_values = saved_changes.transform_values(&:last)

      [previous_values, current_values]
    end

    def build_primary_update_payload(previous_values, current_values)
      encrypted_update_attrs = encrypted_update_attrs(previous_values, current_values)
      @update_payloads << Loggable::Payload.new(
        record: @record, 
        payload_type: 'update_payload',
        encrypted_attrs: encrypted_update_attrs 
        )
    end

    def encrypted_update_attrs(previous_values, current_values)
      changes = []
      changed_attrs = previous_values.slice(*self.class.loggable_attrs)
      # key = Loggable::EncryptionKey.for_record(@record)
      changed_attrs.each do |key, from_value|
        from = Loggable::Encryption.encrypt(from_value, primary_encryption_key) 
        to_value = current_values[key]
        to = Loggable::Encryption.encrypt(to_value, primary_encryption_key)
        changes << { key => { from:, to: }}
      end
      { changes: }
    end

    def build_update_relation_payloads(relation_config)
      relation_config.each do |key, value|
        case key
        when :has_one
        when :has_many
        when 'belongs_to'
           build_relation_update_for_belongs_to(relation_config)
        end
      end
    end


    def build_relation_update_for_belongs_to(relation_config)
      relation_id = "#{relation_config['belongs_to']}_id"
      model_class_name = relation_config['model']
      model_class = model_class_name.constantize

      if saved_changes.include?(relation_id)
        relation_id_changes = saved_changes[relation_id]
        previous_relation_id, current_relation_id = relation_id_changes

        [previous_relation_id, current_relation_id].each_with_index do |relation_id, index|
          relation_record = relation_id ? model_class.find_by(id: relation_id) : nil
          next unless relation_record

          payload_type = index.zero? ? 'previous_association' : 'current_association'
          build_relation_update_payload(
            relation_record.attributes, 
            relation_config['loggable_attrs'],
            relation_record,
            payload_type
          )
        end
      end
    end

    def build_relation_update_payload(attrs, loggable_attrs, record, payload_type)
      key = Loggable::EncryptionKey.for_record(record)
      encrypted_attrs = relation_encrypted_attrs(record.attributes, loggable_attrs, key)

      @update_payloads << Loggable::Payload.new(
        record: record, 
        encrypted_attrs: encrypted_attrs,
        payload_type: payload_type
      )
    end

    def relation_encrypted_attrs(attrs, loggable_attrs, key)
      attrs = attrs.slice(*loggable_attrs)
      encrypt_attrs(attrs, key)
    end
  end
end