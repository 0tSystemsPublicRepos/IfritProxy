package payload

import (
	"log"
)

// AddCondition adds a condition to a payload template
func (pm *PayloadManager) AddCondition(payloadID int, conditionType, conditionValue, operator string) error {
	query := `
		INSERT INTO payload_conditions (payload_template_id, condition_type, condition_value, operator)
		VALUES (?, ?, ?, ?)
	`

	_, err := pm.db.Exec(query, payloadID, conditionType, conditionValue, operator)
	if err != nil {
		log.Printf("Error adding condition: %v", err)
		return err
	}

	return nil
}

// RemoveCondition removes a condition from a payload template
func (pm *PayloadManager) RemoveCondition(conditionID int) error {
	query := `DELETE FROM payload_conditions WHERE id = ?`
	_, err := pm.db.Exec(query, conditionID)
	return err
}

// GetConditionsForPayload retrieves all conditions for a payload
func (pm *PayloadManager) GetConditionsForPayload(payloadID int) ([]PayloadCondition, error) {
	query := `
		SELECT id, condition_type, condition_value, operator
		FROM payload_conditions
		WHERE payload_template_id = ?
		ORDER BY id ASC
	`

	rows, err := pm.db.Query(query, payloadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var conditions []PayloadCondition

	for rows.Next() {
		var id int64
		var conditionType, conditionValue, operator string

		if err := rows.Scan(&id, &conditionType, &conditionValue, &operator); err != nil {
			log.Printf("Error scanning condition: %v", err)
			continue
		}

		conditions = append(conditions, PayloadCondition{
			ID:             id,
			ConditionType:  conditionType,
			ConditionValue: conditionValue,
			Operator:       operator,
		})
	}

	return conditions, nil
}

// UpdateCondition updates an existing condition
func (pm *PayloadManager) UpdateCondition(conditionID int, conditionType, conditionValue, operator string) error {
	query := `
		UPDATE payload_conditions
		SET condition_type = ?, condition_value = ?, operator = ?
		WHERE id = ?
	`

	_, err := pm.db.Exec(query, conditionType, conditionValue, operator, conditionID)
	return err
}
