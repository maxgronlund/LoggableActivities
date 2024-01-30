# frozen_string_literal: true
# This is the main module for loggable. 
# When included to a model, it provides the features for creating the activities.

module Loggable
  module Activities
    extend ActiveSupport::Concern
    include Loggable::PayloadsBuilder
    include Loggable::UpdatePayloadsBuilder
    include Loggable::DataOwnerBuilder

    # has_many :data_owner_encryption_keys, as: :data_owner, class_name: 'Loggable::DataOwnerEncryptionKey'
    # has_many :encryption_keys, through: :data_owner_encryption_keys, class_name: 'Loggable::EncryptionKey'

    included do
      config = Loggable::Configuration.for_class(name)
      raise "Loggable::Configuration not found for #{name}, Please add it to 'config/loggable_activity.yaml'" if config.nil?

      self.loggable_attrs = config&.fetch('loggable_attrs', []) || []
      self.relations = config&.fetch('relations', []) || []
      self.auto_log = config&.fetch('auto_log', []) || []
      self.actor_display_name = config&.fetch('actor_display_name', nil)
      self.record_display_name = config&.fetch('record_display_name', nil)

      after_create :log_create_activity
      after_update :log_update_activity
      before_destroy :log_destroy_activity
    end

    # This is the main method for logging activities.
    # It is never called from the directly from the controller.
    def log(action, actor: nil, params: {})
      @action = action
      @actor = actor || Thread.current[:current_user]

      return if @actor.nil?

      @record = self
      @params = params
      @payloads = []

      case action
      when :create, :show
        log_activity
      when :destroy
        log_destroy
      when :update
        log_update
      else
        log_custom_activity(action)
      end

      build_data_owners
    end

    def delete_data_owner_encryption_keys
      Loggable::DataOwnerEncryptionKey.where(data_owner: self).each(&:encryption_key)
    end

    def data_owner_encryption_keys
      Loggable::DataOwnerEncryptionKey.where(data_owner: self)
    end

    private

    def log_activity
      create_activity(build_payloads)
    end

    def log_update
      create_activity(build_update_payloads)
    end

    def log_destroy
      Loggable::Activity.create!(
        encoded_actor_display_name: encoded_actor_name,
        encoded_record_display_name: '',
        action: action_key,
        actor: @actor,
        record: @record,
        payloads: [
          Loggable::Payload.new(
            record: @record,
            payload_type: 'destroy_payload',
            encrypted_attrs: {}.to_json
          )
        ]
      )
    end
    
    def create_activity(payloads)
      Loggable::Activity.create!(
        encoded_actor_display_name: encoded_actor_name,
        encoded_record_display_name: encoded_record_name,
        action: action_key,
        actor: @actor,
        record: @record,
        payloads: payloads
      )
    end

    def log_custom_activity(activity); end
    
    def log_update_activity
      log(:update) if self.class.auto_log.include?('update')
    end

    def log_create_activity
      log(:create) if self.class.auto_log.include?('create')
    end

    def log_destroy_activity
      Loggable::EncryptionKey.delete_key_for_record(self)
      log(:destroy) if self.class.auto_log.include?('destroy')
    end


    def encoded_record_name
      display_name =
        if self.class.record_display_name.nil?
          "#{self.class.name} id: #{id}"
        else
          send(self.class.record_display_name.to_sym)
        end
      Loggable::Encryption.encrypt(display_name, primary_encryption_key)
    end

    def encoded_actor_name
      actor_display_name = @actor.send(actor_display_name_field)
      Loggable::Encryption.encrypt(actor_display_name, actor_encryption_key)
    end

    def action_key
      @action_key ||= self.class.base_action + ".#{@action}"
    end

    def primary_encryption_key
      Loggable::EncryptionKey.encryption_key_for_record(self)&.encryption_key
    end

    def actor_encryption_key
      Loggable::EncryptionKey.encryption_key_for_record(@actor)&.encryption_key
    end

    def actor_display_name_field
      Rails.application.config.loggable_activity.actor_display_name || "id: #{@actor.id}, class: #{@actor.class.name}"
    end

    def current_user_model?
      Rails.application.config.loggable_activity.current_user_model_name == self.class.name
    end

    class_methods do
      attr_accessor :loggable_attrs, :relations, :auto_log, :record_display_name, :actor_display_name

      def base_action
        name.downcase.gsub('::', '/')
      end
    end
  end
end
