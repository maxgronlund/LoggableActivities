# frozen_string_literal: true

require 'active_record'

module LoggableActivity
  # Represents one action in the activity log.
  class Activity < ActiveRecord::Base
    # Associations
    has_many :payloads, class_name: '::LoggableActivity::Payload', dependent: :destroy
    belongs_to :actor, polymorphic: true, optional: true
    belongs_to :record, polymorphic: true, optional: true

    accepts_nested_attributes_for :payloads

    # Validations
    validates :actor, presence: true
    validates :action, presence: true
    validate :must_have_at_least_one_payload

    RELATION_TYPES = {
      'primary_payload' => 'self',
      'primary_update_payload' => 'self',
      'primary_destroy_payload' => 'self',
      'has_one_payload' => 'has_one',
      'has_one_create_payload' => 'has_one',
      'has_one_update_payload' => 'has_one',
      'has_one_destroy_payload' => 'has_one',
      'has_many_payload' => 'has_many',
      'has_many_create_payload' => 'has_many',
      'has_many_destroy_payload' => 'has_many',
      'has_many_update_payload' => 'has_many',
      'belongs_to_payload' => 'belongs_to',
      'belongs_to_destroy_payload' => 'belongs_to',
      'belongs_to_update_payload' => 'belongs_to',
      'custom_payload' => 'self'
    }.freeze

    def self.ransackable_attributes(_auth_object = nil)
      %w[action actor_display_name actor_id actor_type created_at id id_value record_id record_type updated_at]
    end

    def self.ransackable_associations(_auth_object = nil)
      %w[actor payloads record]
    end

    # Returns an array of hashes, each representing an activity's attributes and its associated relations. The structure and relations to include are specified in 'config/loggable_activity.yaml'. This format is designed for UI display purposes.
    #
    # Each hash in the array contains:
    # - :record_type: The class name of the record.
    # - :related_to_activity_as: A descriptor of the payload's role (e.g., 'primary_payload' or 'current_association').
    # - :attrs: A hash of the record's attributes.
    #
    # Example usage:
    #   @activity.attrs
    #
    # Sample return value:
    #   [
    #     { record_type: MODEL_NAME, related_to_activity_as: "primary_payload", attrs: { "KEY" => "VALUE", ... } },
    #     { record_type: MODEL_NAME, related_to_activity_as: "current_association", attrs: { "KEY" => "VALUE", ... } },
    #     ...
    #   ]
    def attrs
      {
        actor_type:,
        actor_id:,
        action:,
        actor_display_name: fetch_actor_display_name,
        record_display_name:,
        payloads: payloads_attrs
      }
    end

    def payloads_attrs
      ordered_payloads.map do |payload|
        {
          relation: RELATION_TYPES[payload.related_to_activity_as],
          record_type: payload.record_type,
          record_id: payload.deleted? ? nil : payload.record_id,
          attrs: payload.attrs,
          route: payload.payload_route,
          record_display_name: payload.fetch_record_display_name,
          current_payload: payload.current_payload,
          data_owner: payload.data_owner
        }
      end
    end

    # Returns the attributes for the relations.
    #
    # Example:
    #
    #   @activity.relations_attrs
    #
    # Returns:
    #   [
    #     {
    #       record_type: CLASS.NAME,
    #       record_id: INTEGER,
    #       related_to_activity_as: ENUM
    #       attrs: { "KEY_A" => "VALUE_A", "KEY_B" => "VALUE_B", ... }
    #     }
    #   ]
    # def relations_attrs
    #   attrs.filter { |p| p[:related_to_activity_as] == 'current_association' }
    # end

    # Returns the display name for a record. what method to use if defined in '/config/loggable_activity.yaml'
    #
    # Example:
    #
    #   @activity.record_display_name
    #
    # Returns:
    #   "David Bowie"
    #
    def record_display_name
      primary_payload&.fetch_record_display_name
    end

    # Returns the path for the activity.
    #
    # Example:
    #
    #   @activity.path
    #
    # Returns:
    #   "/path/to/activity"
    #
    def primary_route
      primary_payload.payload_route
    end

    # Returns the display name for a actor. what method to use if defined in '/config/loggable_activity.yaml'
    #
    # Example:
    #
    #   @activity.actor_display_name
    #
    # Returns:
    #   "Elvis Presley"
    #
    def fetch_actor_display_name
      return I18n.t('loggable.activity.deleted') if actor_deleted?

      actor_display_name
    end

    # Returns a list of activities for a given actor.
    def self.activities_for_actor(actor, limit = 20, params = { offset: 0 })
      ::LoggableActivity::Activity.latest(limit, params).where(actor:)
    end

    # Returns a list of activities ordered by creation date.
    # This is done to support UUID primary keys.
    def self.latest(limit = 20, params = { offset: 0 })
      offset = params[:offset] || 0
      ::LoggableActivity::Activity
        .all
        .order(created_at: :desc)
        .includes(payloads: :encryption_key)
        .offset(offset)
        .limit(limit)
    end

    # Returns the last activity.
    # This is done to support of UUID primary keys.
    def self.last(limit = 1)
      return latest(1).first if limit == 1

      latest(limit)
    end

    private

    # Returns the primary payload associated with the activity.
    #
    # Example usage:
    #   payload = @activity.primary_payload
    #   payload.record_type  # => 'SOMD_MODEL_NAME'
    #
    def primary_payload
      related_to_activity_as = %w[primary_payload primary_update_payload primary_destroy_payload custom_payload]
      payloads.detect { |p| related_to_activity_as.include?(p.related_to_activity_as) }
    end

    # # Returns payloads sorted by :related_to_activity_as.
    def ordered_payloads
      # payloads.order(related_to_activity_as: :desc)
      payloads
    end

    # Returns the key for the logged record.
    def record_key
      return nil if record.nil?

      ::LoggableActivity::EncryptionKey.for_record(record)&.secret_key
    end

    # Check if the actor is deleted.
    # If the actor is deleted, it will return true.
    # This way we don't rely on access to the main DB to check if the actor is deleted.
    def actor_deleted?
      actor_secret_key.nil?
    end

    # Returns the key for the actor.
    def actor_secret_key
      # @actor_key_secret_key ||=
      ::LoggableActivity::EncryptionKey.for_record_by_type_and_id(actor_type, actor_id)&.secret_key
    end

    # Validates that the activity has at least one payload.
    def must_have_at_least_one_payload
      errors.add(:payloads, 'must have at least one payload') if payloads.empty?
    end
  end
end
