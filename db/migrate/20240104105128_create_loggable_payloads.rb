class CreateLoggablePayloads < ActiveRecord::Migration[7.1]
  def change
    create_table :loggable_payloads, id: :uuid do |t|
      t.uuid :owner
      t.json :attrs
      
      # Manually create a UUID column for the foreign key
      t.uuid :activity_id, null: false

      t.timestamps
    end

    # Add foreign key constraint
    add_foreign_key :loggable_payloads, :loggable_activities, column: :activity_id
  end
end
