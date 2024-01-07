class Loggable::Activity < ApplicationRecord
  has_many :payloads, class_name: 'Loggable::Payload', dependent: :destroy
  accepts_nested_attributes_for :payloads

  validates :actor, presence: true
  validates :action, presence: true

  validate :must_have_at_least_one_payload

  belongs_to :loggable, polymorphic: true, optional: true
  belongs_to :actor, polymorphic: true, optional: false 
  # belongs_to :recipient, polymorphic: true, optional: true

  private

  def must_have_at_least_one_payload
    errors.add(:payloads, 'must have at least one payload') if payloads.empty?
  end
end
