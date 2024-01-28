# frozen_string_literal: true

module Loggable
  class Activity < ApplicationRecord
    has_many :payloads, class_name: 'Loggable::Payload', dependent: :destroy
    accepts_nested_attributes_for :payloads

    validates :actor, presence: true
    validates :action, presence: true

    validate :must_have_at_least_one_payload

    belongs_to :record, polymorphic: true, optional: true
    belongs_to :actor, polymorphic: true, optional: false

    def self.activities_for_actor(actor)
      Loggable::Activity.where(actor:).order(created_at: :desc)
    end

    def self.latest(limit = 20, params = { offset: 0 })
      offset = params[:offset] || 0
      Loggable::Activity
        .all
        .order(created_at: :desc)
        .offset(offset)
        .limit(limit)
    end

    def relations_attrs
      attrs[:relations]
    end

    def attrs
      @attrs ||= payloads_attrs
    end

    def presentation_attrs
      {
        update_attrs: update_attrs,
        updated_relations_attrs: updated_relations 
      }
    end

    def primary_payload_attrs
      payload = payloads.find { |p| p.payload_type == "primary_payload" }
      payload ? payload.attrs : {}
    end

    def relations_attrs
      attrs.filter { |p| p[:payload_type] == "current_association" }
    end

    def updated_relations
      grouped_associations = attrs.group_by { |p| p[:record_type] }

      grouped_associations.map do |record_type, payloads|
        previous_attrs = payloads.find { |p| p[:payload_type] == "previous_association" }
        current_attrs = payloads.find { |p| p[:payload_type] == "current_association" }
        return if previous_attrs.nil? && current_attrs.nil?

        record_class = current_attrs.nil? ? previous_attrs[:record_class] : current_attrs[:record_class]

        {
          record_class: record_class,
          previous_attrs: previous_attrs,
          current_attrs: current_attrs
        }
      end
    end

    def update_attrs
      update_payload_attrs = attrs.find { |p| p[:payload_type] == "update_payload" }
      return nil unless update_payload_attrs

      update_payload_attrs.delete(:payload_type)
      update_payload_attrs
    end

    def previous_associations_attrs
      attrs.select { |p| p[:payload_type] == "previous_association" }
    end


    def actor_display_name
      Loggable::Encryption.decrypt(encoded_actor_display_name, actor_key)
    end


    def actor_key
      Loggable::EncryptionKey.for_record_by_type_and_id(actor_type, actor_id)
    end

    def payloads_attrs
      payloads.order(:payload_type).map do  |payload|
        {
          record_class: payload.record_type,
          payload_type: payload.payload_type,
          attrs: payload.attrs
        }
      end
    end

    def must_have_at_least_one_payload
      errors.add(:payloads, 'must have at least one payload') if payloads.empty?
    end
  end
end
