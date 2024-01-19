# frozen_string_literal: true

class CreateLoggableActivities < ActiveRecord::Migration[7.1]
  def change
    create_table :loggable_activities, id: :uuid do |t|
      t.string :action
      t.uuid :actor_id
      t.string :actor_type
      t.uuid :loggable_id
      t.string :loggable_type
      t.string :owner_name

      t.timestamps
    end
  end
end
