import { ContactsCollection } from '../db/models/contacts.js';
import { logger } from '../app.js';
import { calculatePaginationData } from '../utils/calculatePaginationData.js';

export const findContacts = async ({ page, perPage, sortOrder, sortBy }) => {
  const limit = perPage;
  const skip = page > 0 ? ((page - 1) * perPage) : 0;
  const contactsCount = await ContactsCollection.find().countDocuments();
  const paginationData = calculatePaginationData(contactsCount, page, perPage);
  const contacts = await ContactsCollection.find().sort({[sortBy] : sortOrder}).skip(skip).limit(limit);
  return {
    data: contacts,
    sortOrder,
    sortBy,
    ...paginationData,
  };
};

export const findContactById = async (id) => {
  const data = await ContactsCollection.findById(id);
  return data;
};

export const createContact = async (newContact) => {
  const data = await ContactsCollection.create(newContact);
  return data;
};

export const deleteContact = async (id) => {
  const data = await ContactsCollection.findOneAndDelete({
    _id: id,
  });
  return data;
};

export const upsertContact = async (id, payload, options = {}) => {
  const rawData = await ContactsCollection.findOneAndUpdate(
    { _id: id },
    payload,
    {
      new: true,
      includeResultMetadata: true,
      ...options,
    },
  );

  logger.info(rawData);

  if (!rawData.value) {
    return null;
  }

  return {
    contact: rawData.value,
    isNew: rawData?.lastErrorObject?.upserted,
  };
};
